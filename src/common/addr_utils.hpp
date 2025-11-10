#pragma once

#include <socks5/common/asio.hpp>
#include <fmt/core.h>
#include <proto/proto.hpp>

namespace socks5::common {

// Port size.
constexpr size_t kAddrPortSize{2};
// IPv4 address and port size.
constexpr size_t kIPv4AddrSize{6};
// IPv6 address and port size.
constexpr size_t kIPv6AddrSize{18};

std::string ToString(const proto::Addr& addr);
bool AddrCmp(const proto::Addr& lhs, const proto::Addr& rhs) noexcept;

template <typename T, size_t Size>
bool IsFilledWithZeros(const std::array<T, Size>& arr) noexcept {
  return arr == std::array<T, Size>{};
}

struct EqualTo {
  bool operator()(const proto::Addr& lhs,
                  const proto::Addr& rhs) const noexcept;
};

struct Hash {
  size_t operator()(const proto::Addr& data) const;
};

template <typename Buffer>
void ReadAddr(Buffer& buf, proto::Addr& addr) noexcept {
  buf.Read(addr.atyp);
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      buf.Read(addr.addr.ipv4.addr);
      buf.Read(addr.addr.ipv4.port);
      break;
    }
    case proto::AddrType::kAddrTypeIPv6: {
      buf.Read(addr.addr.ipv6.addr);
      buf.Read(addr.addr.ipv6.port);
      break;
    }
    case proto::AddrType::kAddrTypeDomainName: {
      buf.Read(addr.addr.domain.length);
      buf.Read(addr.addr.domain.addr, addr.addr.domain.length);
      buf.Read(addr.addr.domain.port);
      break;
    }
  }
}

template <typename Buffer>
void Append(Buffer& buf, const proto::Addr& addr) noexcept {
  buf.Append(addr.atyp);
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeDomainName: {
      buf.Append(addr.addr.domain.length);
      buf.Append(addr.addr.domain.addr, addr.addr.domain.length);
      buf.Append(addr.addr.domain.port);
      break;
    }
    case proto::AddrType::kAddrTypeIPv4: {
      buf.Append(addr.addr.ipv4.addr);
      buf.Append(addr.addr.ipv4.port);
      break;
    }
    case proto::AddrType::kAddrTypeIPv6: {
      buf.Append(addr.addr.ipv6.addr);
      buf.Append(addr.addr.ipv6.port);
      break;
    }
  }
}

}  // namespace socks5::common
