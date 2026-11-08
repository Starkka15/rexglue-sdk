/**
 * Skylanders "Portal of Power" support for XamInputNonController{Get,Set}Raw.
 *
 * The 360 Skylanders games talk to the portal through these two XAM calls with
 * raw packets of up to 32 bytes (see xenia-canary src/xenia/hid/portal, BSD).
 * Spyro's Adventure resolves them at run time (XexLoadImage("xam.xex") +
 * XexGetProcedureAddress 1185/1186), then from its portal thread every ~12 ms
 * reads one packet and writes at most one.  360 packets are "0B 14" followed
 * by the usual Wii/PS3 portal command ('R', 'A', 'S', 'Q', 'W', 'C', ...).
 *
 * The packets are not sent to a USB device from here.  They go over a local
 * socket to a portal service (the Decky "Portal of Power" plugin on SteamOS,
 * or tools/skyportal.py on a PC), which forwards them to a real Wii/PS3/360
 * portal or emulates one from figure dumps.  That keeps USB permissions out of
 * the game and lets figures be swapped while the game runs.
 *
 * Wire format: frames of [u8 type][u8 length][length bytes], length <= 32.
 *   game -> service  'W' write packet (as the game sent it, 360 framing)
 *                    'R' read request (length 0)
 *   service -> game  'D' reply to 'R': the next packet, or length 0 for none
 * Every 'R' gets exactly one 'D'; writes get no reply.
 * Socket: $SKYPORTAL_SOCKET; default /tmp/skyportal.sock (Linux) or
 *         TCP 127.0.0.1:47150 (Windows).  "tcp:host:port" works everywhere.
 *
 * Copyright 2026 Starkka15. Released under the BSD license, like the SDK.
 */

#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/runtime.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xtypes.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
static constexpr sock_t kBadSock = INVALID_SOCKET;
static void close_sock(sock_t s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
using sock_t = int;
static constexpr sock_t kBadSock = -1;
static void close_sock(sock_t s) { ::close(s); }
#endif

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;

namespace {

constexpr uint32_t kPortalBufferSize = 0x20;

int EnvInt(const char* name, int def) {
  const char* e = std::getenv(name);
  return e && *e ? std::atoi(e) : def;
}

class PortalLink {
 public:
  static PortalLink& Get() {
    static PortalLink link;
    return link;
  }

  // false when no portal service is reachable.
  bool Write(const uint8_t* data, uint32_t len) {
    std::lock_guard<std::mutex> g(mutex_);
    if (!EnsureConnected()) return false;
    uint8_t frame[2 + kPortalBufferSize];
    frame[0] = 'W';
    frame[1] = static_cast<uint8_t>(len);
    std::memcpy(frame + 2, data, len);
    if (!SendAll(frame, 2 + len)) {
      Drop("write failed");
      return false;
    }
    if (log_left_ > 0) {
      --log_left_;
      LogPacket("portal: game->portal", data, len);
    }
    return true;
  }

  // -1: no service.  Otherwise the byte count copied to out (0 = no packet).
  int Read(uint8_t* out, uint32_t cap) {
    std::lock_guard<std::mutex> g(mutex_);
    if (!EnsureConnected()) return -1;
    const uint8_t req[2] = {'R', 0};
    if (!SendAll(req, 2)) {
      Drop("read request failed");
      return -1;
    }
    uint8_t hdr[2];
    if (!RecvAll(hdr, 2) || hdr[0] != 'D' || hdr[1] > kPortalBufferSize) {
      Drop("bad or missing reply");
      return -1;
    }
    uint8_t body[kPortalBufferSize];
    if (hdr[1] && !RecvAll(body, hdr[1])) {
      Drop("short reply");
      return -1;
    }
    uint32_t n = hdr[1] < cap ? hdr[1] : cap;
    std::memcpy(out, body, n);
    if (n && log_left_ > 0) {
      --log_left_;
      LogPacket("portal: portal->game", body, hdr[1]);
    }
    return static_cast<int>(n);
  }

 private:
  PortalLink() : log_left_(EnvInt("SKYPORTAL_LOG_PACKETS", 200)) {}

  static void LogPacket(const char* what, const uint8_t* d, uint32_t n) {
    char hex[3 * kPortalBufferSize + 1] = {};
    for (uint32_t i = 0; i < n && i < kPortalBufferSize; ++i)
      std::snprintf(hex + i * 3, 4, "%02X ", d[i]);
    REXKRNL_INFO("{} [{}] {}", what, n, hex);
  }

  bool SendAll(const uint8_t* d, size_t n) {
    while (n) {
#if defined(_WIN32)
      int r = ::send(sock_, reinterpret_cast<const char*>(d), static_cast<int>(n), 0);
#else
      ssize_t r = ::send(sock_, d, n, MSG_NOSIGNAL);
#endif
      if (r <= 0) return false;
      d += r;
      n -= static_cast<size_t>(r);
    }
    return true;
  }

  // Waits at most reply_timeout_ms_ in total for the bytes.
  bool RecvAll(uint8_t* d, size_t n) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(reply_timeout_ms_);
    while (n) {
      auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                      deadline - std::chrono::steady_clock::now())
                      .count();
      if (left <= 0) return false;
#if defined(_WIN32)
      fd_set rd;
      FD_ZERO(&rd);
      FD_SET(sock_, &rd);
      timeval tv{static_cast<long>(left / 1000), static_cast<long>((left % 1000) * 1000)};
      if (::select(0, &rd, nullptr, nullptr, &tv) <= 0) return false;
      int r = ::recv(sock_, reinterpret_cast<char*>(d), static_cast<int>(n), 0);
#else
      pollfd p{sock_, POLLIN, 0};
      if (::poll(&p, 1, static_cast<int>(left)) <= 0) return false;
      ssize_t r = ::recv(sock_, d, n, 0);
#endif
      if (r <= 0) return false;
      d += r;
      n -= static_cast<size_t>(r);
    }
    return true;
  }

  // Caller holds mutex_.  Retries at most once a second while disconnected.
  bool EnsureConnected() {
    if (sock_ != kBadSock) return true;
    auto now = std::chrono::steady_clock::now();
    if (tried_ && now - last_attempt_ < std::chrono::seconds(1)) return false;
    tried_ = true;
    last_attempt_ = now;

    const char* env = std::getenv("SKYPORTAL_SOCKET");
    std::string addr = env && *env ? env : "";
#if defined(_WIN32)
    static bool wsa = [] {
      WSADATA w;
      return WSAStartup(MAKEWORD(2, 2), &w) == 0;
    }();
    (void)wsa;
    if (addr.empty()) addr = "tcp:127.0.0.1:47150";
#else
    if (addr.empty()) addr = "/tmp/skyportal.sock";
#endif
    sock_t s = kBadSock;
    if (addr.rfind("tcp:", 0) == 0) {
      std::string hp = addr.substr(4);
      auto colon = hp.rfind(':');
      std::string host = hp.substr(0, colon);
      int port = std::atoi(hp.c_str() + colon + 1);
      s = ::socket(AF_INET, SOCK_STREAM, 0);
      if (s != kBadSock) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
        if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
          close_sock(s);
          s = kBadSock;
        }
      }
    }
#if !defined(_WIN32)
    else {
      s = ::socket(AF_UNIX, SOCK_STREAM, 0);
      if (s != kBadSock) {
        sockaddr_un sa{};
        sa.sun_family = AF_UNIX;
        std::strncpy(sa.sun_path, addr.c_str(), sizeof(sa.sun_path) - 1);
        if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
          close_sock(s);
          s = kBadSock;
        }
      }
    }
#endif
    if (s == kBadSock) {
      if (!warned_) {
        REXKRNL_INFO("portal: no portal service at {} (retrying every second)", addr);
        warned_ = true;
      }
      return false;
    }
    sock_ = s;
    warned_ = false;
    REXKRNL_INFO("portal: connected to portal service at {}", addr);
    return true;
  }

  void Drop(const char* why) {
    if (sock_ == kBadSock) return;
    REXKRNL_INFO("portal: disconnected from portal service ({})", why);
    close_sock(sock_);
    sock_ = kBadSock;
  }

  std::mutex mutex_;
  sock_t sock_ = kBadSock;
  bool tried_ = false;
  bool warned_ = false;
  std::chrono::steady_clock::time_point last_attempt_{};
  int reply_timeout_ms_ = EnvInt("SKYPORTAL_REPLY_TIMEOUT_MS", 250);
  int log_left_;
};

}  // namespace

u32 XamInputNonControllerGetRawEx_entry(u32 device_id, mapped_u32 buffer_ptr,
                                        mapped_u32 buffer_length_ptr, mapped_u16 state_ptr) {
  if (device_id != 5 && device_id != 6) return X_ERROR_INVALID_PARAMETER;
  if (!state_ptr || !buffer_length_ptr || !buffer_ptr) return X_ERROR_INVALID_PARAMETER;
  uint32_t cap = *buffer_length_ptr;
  if (cap == 0 || cap > kPortalBufferSize) return X_ERROR_INVALID_PARAMETER;

  uint8_t tmp[kPortalBufferSize];
  int n = PortalLink::Get().Read(tmp, cap);
  if (n < 0) return X_ERROR_DEVICE_NOT_CONNECTED;
  std::memcpy(reinterpret_cast<uint8_t*>(buffer_ptr.host_address()), tmp, static_cast<size_t>(n));
  *buffer_length_ptr = static_cast<uint32_t>(n);
  // Spyro's Adventure only parses a packet when state != 0.
  *state_ptr = n ? 1 : 0;
  return X_ERROR_SUCCESS;
}

u32 XamInputNonControllerSetRawEx_entry(u32 device_id, mapped_u32 buffer_ptr, u32 buffer_length) {
  if (device_id != 5 && device_id != 6) return X_ERROR_INVALID_PARAMETER;
  if (!buffer_ptr || !buffer_length || buffer_length > kPortalBufferSize)
    return X_ERROR_INVALID_PARAMETER;
  if (!PortalLink::Get().Write(reinterpret_cast<const uint8_t*>(buffer_ptr.host_address()),
                               buffer_length))
    return X_ERROR_DEVICE_NOT_CONNECTED;
  return X_ERROR_SUCCESS;
}

u32 XamInputNonControllerGetRaw_entry(mapped_u16 state_ptr, mapped_u32 buffer_length_ptr,
                                      mapped_u32 buffer_ptr) {
  return XamInputNonControllerGetRawEx_entry(5, buffer_ptr, buffer_length_ptr, state_ptr);
}

u32 XamInputNonControllerSetRaw_entry(u32 buffer_length, mapped_u32 buffer_ptr) {
  return XamInputNonControllerSetRawEx_entry(5, buffer_ptr, buffer_length);
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamInputNonControllerGetRaw, rex::kernel::xam::XamInputNonControllerGetRaw_entry)
REX_EXPORT(__imp__XamInputNonControllerGetRawEx,
           rex::kernel::xam::XamInputNonControllerGetRawEx_entry)
REX_EXPORT(__imp__XamInputNonControllerSetRaw, rex::kernel::xam::XamInputNonControllerSetRaw_entry)
REX_EXPORT(__imp__XamInputNonControllerSetRawEx,
           rex::kernel::xam::XamInputNonControllerSetRawEx_entry)
