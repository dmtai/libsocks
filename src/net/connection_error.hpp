#pragma once

#include <exception>
#include <string>
#include <variant>
#include <socks5/common/asio.hpp>
#include <fmt/core.h>

namespace socks5::net {

class TcpConnection;
class UdpConnection;
const std::string& ToString(TcpConnection& connect) noexcept;
const std::string& ToString(UdpConnection& connect) noexcept;

class ConnectionError final {
 public:
  using Error = std::variant<std::monostate, boost::system::error_code,
                             std::exception_ptr>;

  template <typename T>
  ConnectionError(std::string_view hdr, T err) noexcept
      : hdr_{std::move(hdr)}, error_{std::move(err)} {}

  ConnectionError(std::string_view hdr) noexcept;

  std::string Msg() const noexcept;

 private:
  std::string MakeMsg(const boost::system::error_code& err) const;
  std::string MakeMsg(std::exception_ptr err) const;
  std::string MakeMsg([[maybe_unused]] std::monostate err) const;
  const char* GetExceptionMsg(std::exception_ptr err) const noexcept;

  std::string_view hdr_;
  Error error_;
};

using TcpConnectErrorOpt = std::optional<ConnectionError>;
using UdpConnectErrorOpt = std::optional<ConnectionError>;
using TcpConnectErrorOptAwait = asio::awaitable<TcpConnectErrorOpt>;
using UdpConnectErrorOptAwait = asio::awaitable<UdpConnectErrorOpt>;

template <typename T>
ConnectionError MakeError(std::string_view hdr, T err) noexcept {
  return {hdr, err};
}

ConnectionError MakeError(std::string_view hdr) noexcept;

template <typename Connection>
std::string MakeErrorMsg(const ConnectionError& err,
                         Connection& connection) noexcept {
  try {
    return fmt::format("{}. {}", err.Msg(), ToString(connection));
  } catch (const std::exception& ex) {
    return ex.what();
  }
}

}  // namespace socks5::net