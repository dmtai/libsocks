#include <socks5/common/address.hpp>
#include <proto/proto.hpp>
#include <common/proto_builders.hpp>
#include <common/addr_utils.hpp>
#include <net/utils.hpp>
#include <common/defs.hpp>
#include <serializers/serializers.hpp>
#include <parsers/parsers.hpp>

namespace socks5::common {

namespace {

constexpr size_t kAddrMaxLen{256};
constexpr size_t kAddrAtypOffset{0};
constexpr size_t kDomainAddrOffset{2};
constexpr size_t kDomainAddrLengthOffset{1};
constexpr size_t kAddrIPv4PortOffset{5};
constexpr size_t kAddrIPv6PortOffset{17};

}  // namespace

struct Address::Impl {
  mutable AddrBufOpt addr;
};

Address::Address() noexcept : impl_{std::nullopt} {};

Address::Address(const Address& other) noexcept {
  impl_->addr = other.impl_->addr;
}

Address& Address::operator=(const Address& other) noexcept {
  if (this == &other) {
    return *this;
  }
  impl_->addr = other.impl_->addr;
  return *this;
}

Address::Address(Address&& other) noexcept {
  impl_->addr = std::move(other.impl_->addr);
  other.impl_->addr = std::nullopt;
}

Address& Address::operator=(Address&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  impl_->addr = std::move(other.impl_->addr);
  other.impl_->addr = std::nullopt;
  return *this;
}

Address::~Address() = default;

Address::Address(std::string_view addr, unsigned short port) {
  const auto addr_size = addr.size();
  if (addr_size == 0 || addr_size > kAddrMaxLen) {
    throw std::runtime_error{"Invalid addr size"};
  }
  boost::system::error_code err;
  const auto asio_addr = asio::ip::make_address(addr, err);
  if (!err) {
    impl_->addr.emplace(
        serializers::Serialize(common::MakeAddr(asio_addr, port)));
    return;
  }
  impl_->addr.emplace(serializers::Serialize(common::MakeAddr(addr, port)));
}

Address::Address(const tcp::endpoint& ep) {
  impl_->addr.emplace(
      serializers::Serialize(common::MakeAddr(ep.address(), ep.port())));
}
Address::Address(const udp::endpoint& ep) {
  impl_->addr.emplace(
      serializers::Serialize(common::MakeAddr(ep.address(), ep.port())));
}

Address::Address(proto::Addr addr) noexcept {
  impl_->addr.emplace(serializers::Serialize(addr));
}

std::string Address::ToString() const {
  if (!impl_->addr) {
    return {};
  }
  return common::ToString(parsers::ParseAddr(*impl_->addr));
}

template <typename T>
T::endpoint Address::ToEndpoint() const {
  if (!IsIP() || !impl_->addr) {
    throw std::runtime_error{"The address doesn't contain an IP address"};
  }
  return net::MakeEndpointFromIP<T>(parsers::ParseAddr(*impl_->addr));
}

proto::Addr Address::ToProtoAddr() const noexcept {
  if (!impl_->addr) {
    return {};
  }
  return parsers::ParseAddr(*impl_->addr);
}

const utils::Buffer& Address::Serialize() const noexcept {
  if (!impl_->addr) {
    static utils::Buffer buf{nullptr, 0};
    return buf;
  }
  return static_cast<const utils::Buffer&>(*impl_->addr);
}

bool Address::IsIP() const noexcept {
  if (!impl_->addr) {
    return false;
  }
  const auto atyp =
      static_cast<uint8_t>(*(impl_->addr->BeginRead() + kAddrAtypOffset));
  return atyp == proto::AddrType::kAddrTypeIPv4 ||
         atyp == proto::AddrType::kAddrTypeIPv6;
}

bool Address::IsDomain() const noexcept {
  if (!impl_->addr) {
    return false;
  }
  const auto atyp =
      static_cast<uint8_t>(*(impl_->addr->BeginRead() + kAddrAtypOffset));
  return atyp == proto::AddrType::kAddrTypeDomainName;
}

std::optional<std::string_view> Address::ToDomain() const noexcept {
  if (!impl_->addr) {
    return std::nullopt;
  }
  const auto addr = impl_->addr->Begin();
  const auto addr_atyp = *reinterpret_cast<uint8_t*>(addr);
  if (addr_atyp != proto::AddrType::kAddrTypeDomainName) {
    return std::nullopt;
  }
  return std::string_view{
      reinterpret_cast<const char*>(addr + kDomainAddrOffset),
      *reinterpret_cast<uint8_t*>(addr + kDomainAddrLengthOffset)};
}

bool Address::IsEmpty() const noexcept { return impl_->addr == std::nullopt; }

std::optional<unsigned short> Address::Port() const noexcept {
  if (!impl_->addr) {
    return std::nullopt;
  }
  const auto begin = impl_->addr->BeginRead();
  const auto atyp = static_cast<uint8_t>(*(begin + kAddrAtypOffset));
  switch (atyp) {
    case proto::AddrType::kAddrTypeIPv4: {
      return asio::detail::socket_ops::network_to_host_short(
          *(reinterpret_cast<unsigned short*>(begin + kAddrIPv4PortOffset)));
    }
    case proto::AddrType::kAddrTypeIPv6: {
      return asio::detail::socket_ops::network_to_host_short(
          *(reinterpret_cast<unsigned short*>(begin + kAddrIPv6PortOffset)));
    }
    case proto::AddrType::kAddrTypeDomainName: {
      const auto rerrr =
          static_cast<uint8_t>(*(begin + kDomainAddrLengthOffset));
      return asio::detail::socket_ops::network_to_host_short(
          *(reinterpret_cast<unsigned short*>(
              begin + kDomainAddrOffset +
              static_cast<uint8_t>(*(begin + kDomainAddrLengthOffset)))));
    }
  }
  return std::nullopt;
}

bool operator==(const Address& lhs, const Address& rhs) noexcept {
  if (!lhs.impl_->addr && !lhs.impl_->addr) {
    return true;
  }
  if (!lhs.impl_->addr || !lhs.impl_->addr) {
    return false;
  }
  return *lhs.impl_->addr == *rhs.impl_->addr;
}

template tcp::endpoint Address::ToEndpoint<tcp>() const;
template udp::endpoint Address::ToEndpoint<udp>() const;

}  // namespace socks5::common