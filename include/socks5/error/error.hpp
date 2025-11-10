#pragma once

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <socks5/common/api_macro.hpp>

namespace socks5::error {

enum class SOCKS5_API Error {
  kSucceeded = 0,
  kGeneralFailure,
  kConnectionNotAllowedByRuleset,
  kNetworkUnreachable,
  kHostUnreachable,
  kConnectionRefused,
  kTtlExpired,
  kCommandNotSupported,
  kAddressTypeNotSupported,
  kAuthFailure,
  kTimeoutExpired,
  kInvalidDatagram,
  kDomainResolutionFailure,
  kCancellationFailure,
  kInvalidAddress,
};

SOCKS5_API boost::system::error_code make_error_code(Error err) noexcept;
SOCKS5_API boost::system::error_code MakeError(uint8_t reply_rep) noexcept;

}  // namespace socks5::error

namespace std {

template <>
struct is_error_code_enum<socks5::error::Error> : true_type {};

}  // namespace std