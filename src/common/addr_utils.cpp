#include <common/addr_utils.hpp>
#include <boost/functional/hash.hpp>

namespace socks5::common {

std::string ToString(const proto::Addr& addr) {
  switch (addr.atyp) {
    case proto::AddrType::kAddrTypeDomainName: {
      return fmt::format("{}:{}",
                         std::string_view{reinterpret_cast<const char*>(
                                              addr.addr.domain.addr.data()),
                                          addr.addr.domain.length},
                         asio::detail::socket_ops::network_to_host_short(
                             addr.addr.domain.port));
    }
    case proto::AddrType::kAddrTypeIPv4: {
      return fmt::format(
          "{}:{}", asio::ip::make_address_v4(addr.addr.ipv4.addr).to_string(),
          asio::detail::socket_ops::network_to_host_short(addr.addr.ipv4.port));
    }
    case proto::AddrType::kAddrTypeIPv6: {
      return fmt::format(
          "[{}]:{}", asio::ip::make_address_v6(addr.addr.ipv6.addr).to_string(),
          asio::detail::socket_ops::network_to_host_short(addr.addr.ipv6.port));
    }
  }
  return "";
}

bool AddrCmp(const proto::Addr& lhs, const proto::Addr& rhs) noexcept {
  if (lhs.atyp != rhs.atyp) {
    return false;
  }
  switch (lhs.atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      return lhs.addr.ipv4.addr == rhs.addr.ipv4.addr &&
             lhs.addr.ipv4.port == rhs.addr.ipv4.port;
    }
    case proto::AddrType::kAddrTypeIPv6: {
      return lhs.addr.ipv6.addr == rhs.addr.ipv6.addr &&
             lhs.addr.ipv6.port == rhs.addr.ipv6.port;
    }
    case proto::AddrType::kAddrTypeDomainName: {
      return lhs.addr.domain.length == rhs.addr.domain.length &&
             lhs.addr.domain.port == rhs.addr.domain.port &&
             (std::memcmp(lhs.addr.domain.addr.data(),
                          rhs.addr.domain.addr.data(),
                          lhs.addr.domain.length) == 0);
    }
  }
  return false;
}

bool EqualTo::operator()(const proto::Addr& lhs,
                         const proto::Addr& rhs) const noexcept {
  if (lhs.atyp == proto::AddrType::kAddrTypeIPv4 &&
      rhs.atyp == proto::AddrType::kAddrTypeIPv4) {
    return lhs.addr.ipv4.addr == rhs.addr.ipv4.addr &&
           lhs.addr.ipv4.port == rhs.addr.ipv4.port;
  } else if (lhs.atyp == proto::AddrType::kAddrTypeIPv6 &&
             rhs.atyp == proto::AddrType::kAddrTypeIPv6) {
    return lhs.addr.ipv6.addr == rhs.addr.ipv6.addr &&
           lhs.addr.ipv6.port == rhs.addr.ipv6.port;
  } else if (lhs.atyp == proto::AddrType::kAddrTypeDomainName &&
             rhs.atyp == proto::AddrType::kAddrTypeDomainName) {
    return (std::string_view{
                reinterpret_cast<const char*>(lhs.addr.domain.addr.data()),
                lhs.addr.domain.length} ==
            std::string_view{
                reinterpret_cast<const char*>(rhs.addr.domain.addr.data()),
                rhs.addr.domain.length}) &&
           lhs.addr.domain.port == rhs.addr.domain.port;
  }
  return false;
}

size_t Hash::operator()(const proto::Addr& data) const {
  size_t seed{};
  if (data.atyp == proto::AddrType::kAddrTypeIPv4) {
    boost::hash_combine(seed, data.addr.ipv4.addr);
    boost::hash_combine(seed, data.addr.ipv4.port);
  } else if (data.atyp == proto::AddrType::kAddrTypeIPv6) {
    boost::hash_combine(seed, data.addr.ipv6.addr);
    boost::hash_combine(seed, data.addr.ipv6.port);
  } else if (data.atyp == proto::AddrType::kAddrTypeDomainName) {
    boost::hash_combine(
        seed, std::string_view{
                  reinterpret_cast<const char*>(data.addr.domain.addr.data()),
                  data.addr.domain.length});
    boost::hash_combine(seed, data.addr.domain.port);
  } else {
    assert(false);
  }
  return seed;
}

}  // namespace socks5::common