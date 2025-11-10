#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <common/defs.hpp>
#include <common/addr_utils.hpp>
#include <socks5/error/error.hpp>
#include <net/io.hpp>

namespace socks5::client {

using ServerChoiceOrError = utils::ErrorOr<ServerChoiceOpt>;
using ServerChoiceOrErrorAwait = asio::awaitable<ServerChoiceOrError>;

using ReplyOrError = utils::ErrorOr<ReplyOpt>;
using ReplyOrErrorAwait = asio::awaitable<ReplyOrError>;

class Handshake {
 public:
  Handshake(tcp::socket& socket,
            const auth::client::AuthOptions& auth_options) noexcept;

  ReplyOrErrorAwait ReadReply() noexcept;
  ErrorAwait Auth() noexcept;
  ServerChoiceOrErrorAwait ReadServerChoice() noexcept;

  template <typename Buffer>
  ErrorAwait ReadIPv4Addr(Buffer& buf) noexcept {
    co_return co_await net::Read(socket_, buf, common::kIPv4AddrSize);
  }

  template <typename Buffer>
  ErrorAwait ReadIPv6Addr(Buffer& buf) noexcept {
    co_return co_await net::Read(socket_, buf, common::kIPv6AddrSize);
  }

  template <typename Buffer>
  ErrorAwait ReadDomainAddr(Buffer& buf) noexcept {
    if (const auto err = co_await net::Read(
            socket_, buf, sizeof(decltype(proto::Domain::length)))) {
      co_return err;
    }
    if (const auto err = co_await net::Read(
            socket_, buf,
            buf.template ReadFromEnd<decltype(proto::Domain::length)>() +
                common::kAddrPortSize)) {
      co_return err;
    }
    co_return error::Error::kSucceeded;
  }

  template <typename Buffer>
  ErrorAwait ReadAddr(Buffer& buf, const proto::AddrType& atyp) noexcept {
    switch (atyp) {
      default: {
        co_return error::Error::kAddressTypeNotSupported;
      }
      case proto::AddrType::kAddrTypeIPv4: {
        co_return co_await ReadIPv4Addr(buf);
      }
      case proto::AddrType::kAddrTypeIPv6: {
        co_return co_await ReadIPv6Addr(buf);
      }
      case proto::AddrType::kAddrTypeDomainName: {
        co_return co_await ReadDomainAddr(buf);
      }
    }
  }

 protected:
  tcp::socket& socket_;
  const auth::client::AuthOptions& auth_options_;
};

}  // namespace socks5::client