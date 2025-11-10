#include <gtest/gtest.h>
#include <socks5/common/address.hpp>
#include <socks5/common/asio.hpp>
#include <proto/proto.hpp>

namespace socks5::common {

TEST(AddressTest, DefaultConstructor) {
  Address addr;
  EXPECT_TRUE(addr.IsEmpty());
  EXPECT_FALSE(addr.IsIP());
  EXPECT_FALSE(addr.IsDomain());
}

TEST(AddressTest, IPv4Construction) {
  Address addr{"192.168.1.1", 8080};
  EXPECT_TRUE(addr.IsIP());
  EXPECT_FALSE(addr.IsDomain());
  EXPECT_FALSE(addr.IsEmpty());
  EXPECT_EQ(addr.Port(), 8080);
  EXPECT_EQ(addr.ToString(), "192.168.1.1:8080");
}

TEST(AddressTest, IPv6Construction) {
  Address addr{"2001:db8::1", 443};
  EXPECT_TRUE(addr.IsIP());
  EXPECT_FALSE(addr.IsDomain());
  EXPECT_FALSE(addr.IsEmpty());
  EXPECT_EQ(addr.Port(), 443);
  EXPECT_EQ(addr.ToString(), "[2001:db8::1]:443");
}

TEST(AddressTest, DomainConstruction) {
  Address addr{"example.com", 80};
  EXPECT_FALSE(addr.IsIP());
  EXPECT_TRUE(addr.IsDomain());
  EXPECT_FALSE(addr.IsEmpty());
  EXPECT_EQ(addr.Port(), 80);
  EXPECT_EQ(addr.ToString(), "example.com:80");
}

TEST(AddressTest, TCPEndpointConstruction) {
  asio::ip::tcp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
  Address addr{ep};

  EXPECT_TRUE(addr.IsIP());
  EXPECT_EQ(addr.ToString(), "10.0.0.1:1234");
}

TEST(AddressTest, UDPEndpointConstruction) {
  asio::ip::udp::endpoint ep{asio::ip::make_address("::1"), 53};
  Address addr{ep};

  EXPECT_TRUE(addr.IsIP());
  EXPECT_EQ(addr.ToString(), "[::1]:53");
}

TEST(AddressTest, ProtoAddrConstruction) {
  proto::Addr proto_addr;
  proto_addr.atyp = proto::AddrType::kAddrTypeIPv4;
  proto_addr.addr.ipv4.addr = {192, 168, 0, 1};
  proto_addr.addr.ipv4.port = htons(8080);

  Address addr{proto_addr};
  EXPECT_TRUE(addr.IsIP());
  EXPECT_EQ(addr.ToString(), "192.168.0.1:8080");
}

TEST(AddressTest, CopySemantics) {
  Address original{"test.org", 443};
  Address copy{original};

  EXPECT_EQ(original, copy);
  EXPECT_EQ(copy.ToString(), "test.org:443");
}

TEST(AddressTest, MoveSemantics) {
  Address original{"move.me", 8080};
  Address moved{std::move(original)};

  EXPECT_TRUE(original.IsEmpty());
  EXPECT_EQ(moved.ToString(), "move.me:8080");
}

TEST(AddressTest, ToProtoAddrConversion) {
  Address addr{"8.8.8.8", 53};
  const auto proto_addr = addr.ToProtoAddr();

  EXPECT_EQ(proto_addr.atyp, proto::AddrType::kAddrTypeIPv4);
  EXPECT_EQ(proto_addr.addr.ipv4.addr, (std::array<uint8_t, 4>{8, 8, 8, 8}));
  EXPECT_EQ(ntohs(proto_addr.addr.ipv4.port), 53);
}

TEST(AddressTest, Serialization) {
  constexpr std::string_view kDomainName{"serialize.me"};
  Address addr{kDomainName, 9999};
  const auto& buffer = addr.Serialize();
  const auto serialized_domain_addr_size = kDomainName.size() + 4;

  EXPECT_GT(buffer.Size(), 0);
  EXPECT_GE(buffer.ReadableBytes(), serialized_domain_addr_size);
}

TEST(AddressTest, ToDomain) {
  Address ip_addr{"127.0.0.1", 80};
  EXPECT_FALSE(ip_addr.ToDomain().has_value());

  Address domain_addr{"google.com", 443};
  const auto domain = domain_addr.ToDomain();
  ASSERT_TRUE(domain.has_value());
  EXPECT_EQ(domain, "google.com");
}

TEST(AddressTest, ToEndpoint) {
  Address ipv4_addr{"192.168.1.100", 8080};
  const auto tcp_ep = ipv4_addr.ToEndpoint<asio::ip::tcp>();
  EXPECT_EQ(tcp_ep.address().to_string(), "192.168.1.100");
  EXPECT_EQ(tcp_ep.port(), 8080);

  Address ipv6_addr{"::1", 1234};
  const auto udp_ep = ipv6_addr.ToEndpoint<asio::ip::udp>();
  EXPECT_EQ(udp_ep.address().to_string(), "::1");
  EXPECT_EQ(udp_ep.port(), 1234);

  Address domain_addr{"invalid.for.endpoint", 80};
  EXPECT_THROW(domain_addr.ToEndpoint<asio::ip::tcp>(), std::exception);
}

TEST(AddressTest, EqualityOperator) {
  Address addr1{"same.com", 80};
  Address addr2{"same.com", 80};
  Address addr3{"different.com", 80};
  Address addr4{"same.com", 443};

  EXPECT_EQ(addr1, addr2);
  EXPECT_NE(addr1, addr3);
  EXPECT_NE(addr1, addr4);
}

TEST(AddressTest, InvalidAddressHandling) {
  EXPECT_THROW(Address("", 80), std::exception);
}

TEST(AddressTest, PortBoundaries) {
  Address min_port{"port.test", 1};
  Address max_port{"port.test", 65535};

  EXPECT_EQ(min_port.ToString(), "port.test:1");
  EXPECT_EQ(max_port.ToString(), "port.test:65535");
}

}  // namespace socks5::common