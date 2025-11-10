#pragma once

#include <stddef.h>
#include <utility>
#include <vector>
#include <string>
#include <memory>
#include <socks5/common/api_macro.hpp>

namespace socks5::server {

using ListenerAddr = std::pair<std::string, unsigned short>;

/**
 * @brief Socks5 proxy server config. The specified default values are used by
 * the socks5 proxy server by default. Configured via ServerBuilder.
 */
struct SOCKS5_API Config final {
  // Timeout in seconds for establishing socks5 connection(client greeting,
  // server choice, authentication, client request, server reply).
  size_t handshake_timeout{5};
  // Timeout in seconds on socket io during tcp relay(CONNECT, BIND commands).
  size_t tcp_relay_timeout{15};
  // Number of server threads.
  size_t threads_num{1};
  // Is it necessary to validate the accepted connection(BIND command).
  bool bind_validate_accepted_conn{false};
  // Timeout in seconds on socket io during udp relay(UDP ASSOCIATE command).
  size_t udp_relay_timeout{15};
  // IPv4/IPv6 address and port pair for proxy server listener. IP "0.0.0.0" is
  // not supported.
  ListenerAddr listener_addr{"127.0.0.1", 1080};
  // Enable Username/Password authentication.
  bool enable_user_auth{false};
  // Authentication username.
  std::string auth_username;
  // Authentication password.
  std::string auth_password;
  // Enable TCP_NODELAY socket option(Nagle's algorithm).
  bool tcp_nodelay{false};
};

using ConfigPtr = std::shared_ptr<Config>;

}  // namespace socks5::server