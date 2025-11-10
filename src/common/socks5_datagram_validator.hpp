#pragma once

#include <common/defs.hpp>
#include <common/socks5_datagram_validator.hpp>
#include <common/addr_utils.hpp>

namespace socks5::common {

namespace detail {

constexpr size_t kDatagramFirst2FieldsSize{3};
constexpr size_t kDatagramFirst3FieldsSize{4};
constexpr size_t kDatagramFirst3FieldsAndDomainLenSize{5};
constexpr size_t kDomainAddrPortSize{2};
constexpr size_t kDomainAddrLengthSize{1};

}  // namespace detail

template <typename T>
bool ValidateDatagramLength(const T& buf) noexcept {
  size_t datagram_header_len{detail::kDatagramFirst3FieldsSize};
  const auto datagram_size = buf.ReadableBytes();
  if (datagram_size < detail::kDatagramFirst3FieldsSize) {
    return false;
  }
  const auto atyp = *(buf.BeginRead() + detail::kDatagramFirst2FieldsSize);
  switch (atyp) {
    default: {
      return false;
    }
    case proto::AddrType::kAddrTypeIPv4: {
      datagram_header_len += kIPv4AddrSize;
      break;
    }
    case proto::AddrType::kAddrTypeIPv6: {
      datagram_header_len += kIPv6AddrSize;
      break;
    }
    case proto::AddrType::kAddrTypeDomainName: {
      if (datagram_size < detail::kDatagramFirst3FieldsAndDomainLenSize) {
        return false;
      }
      datagram_header_len += static_cast<uint8_t>(
          *(buf.BeginRead() + detail::kDatagramFirst3FieldsSize));
      datagram_header_len +=
          detail::kDomainAddrPortSize + detail::kDomainAddrLengthSize;
      break;
    }
  }
  return datagram_size > datagram_header_len;
}

}  // namespace socks5::common