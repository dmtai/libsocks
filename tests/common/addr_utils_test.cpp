#include <gtest/gtest.h>
#include <common/addr_utils.hpp>
#include <socks5/common/asio.hpp>
#include <proto/proto.hpp>
#include <socks5/utils/buffer.hpp>
#include <array>

namespace socks5::common {

namespace {

proto::Addr CreateIPv4Addr(const std::array<uint8_t, 4>& ip, uint16_t port) {
  proto::Addr addr{};
  addr.atyp = proto::AddrType::kAddrTypeIPv4;
  addr.addr.ipv4.addr = ip;
  addr.addr.ipv4.port = port;
  return addr;
}

proto::Addr CreateIPv6Addr(const std::array<uint8_t, 16>& ip, uint16_t port) {
  proto::Addr addr{};
  addr.atyp = proto::AddrType::kAddrTypeIPv6;
  addr.addr.ipv6.addr = ip;
  addr.addr.ipv6.port = port;
  return addr;
}

proto::Addr CreateDomainAddr(const std::string& domain, uint16_t port) {
  proto::Addr addr{};
  addr.atyp = proto::AddrType::kAddrTypeDomainName;
  addr.addr.domain.length = static_cast<uint8_t>(domain.size());
  std::memcpy(addr.addr.domain.addr.data(), domain.data(), domain.size());
  addr.addr.domain.port = port;
  return addr;
}

}  // namespace

TEST(AddrUtilsTest, ToStringIPv4) {
  const auto addr = CreateIPv4Addr({192, 168, 1, 1}, 36895);
  EXPECT_EQ(ToString(addr), "192.168.1.1:8080");
}

TEST(AddrUtilsTest, ToStringIPv6) {
  const auto addr =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     47873);
  EXPECT_EQ(ToString(addr), "[2001:db8:85a3::8a2e:370:7334]:443");
}

TEST(AddrUtilsTest, ToStringDomain) {
  const auto addr = CreateDomainAddr("example.com", 20480);
  EXPECT_EQ(ToString(addr), "example.com:80");
}

TEST(AddrUtilsTest, AddrCmpSameIPv4) {
  const auto addr1 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto addr2 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  EXPECT_TRUE(AddrCmp(addr1, addr2));
}

TEST(AddrUtilsTest, AddrCmpDifferentIPv4) {
  const auto addr1 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto addr2 = CreateIPv4Addr({10, 0, 0, 1}, 8080);
  EXPECT_FALSE(AddrCmp(addr1, addr2));
}

TEST(AddrUtilsTest, AddrCmpDifferentTypes) {
  const auto ipv4 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto domain = CreateDomainAddr("192.168.1.1", 8080);
  EXPECT_FALSE(AddrCmp(ipv4, domain));
}

TEST(AddrUtilsTest, EqualToIPv6) {
  const auto addr1 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  const auto addr2 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  EqualTo equal_to;
  EXPECT_TRUE(equal_to(addr1, addr2));

  const auto addr3 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     444);
  const auto addr4 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  EXPECT_FALSE(equal_to(addr3, addr4));
}

TEST(AddrUtilsTest, EqualToIPv4) {
  const auto addr1 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto addr2 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  EqualTo equal_to;
  EXPECT_TRUE(equal_to(addr1, addr2));

  const auto addr3 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto addr4 = CreateIPv4Addr({192, 168, 1, 2}, 8081);
  EXPECT_FALSE(equal_to(addr3, addr4));
}

TEST(AddrUtilsTest, EqualToDomain) {
  const auto addr1 = CreateDomainAddr("example.com", 80);
  const auto addr2 = CreateDomainAddr("example.com", 80);
  EqualTo equal_to;
  EXPECT_TRUE(equal_to(addr1, addr2));

  const auto addr3 = CreateDomainAddr("example.com", 80);
  const auto addr4 = CreateDomainAddr("example1.com", 80);
  EXPECT_FALSE(equal_to(addr3, addr4));
}

TEST(AddrUtilsTest, HashSameDomain) {
  const auto addr1 = CreateDomainAddr("example.com", 80);
  const auto addr2 = CreateDomainAddr("example.com", 80);
  Hash hash;
  EXPECT_EQ(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, HashSameIPv4) {
  const auto addr1 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto addr2 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  Hash hash;
  EXPECT_EQ(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, HashSameIPv6) {
  const auto addr1 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  const auto addr2 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  Hash hash;
  EXPECT_EQ(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, HashDifferentDomains) {
  const auto addr1 = CreateDomainAddr("example1.com", 80);
  const auto addr2 = CreateDomainAddr("example2.com", 80);
  Hash hash;
  EXPECT_NE(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, HashDifferentIPv4) {
  const auto addr1 = CreateIPv4Addr({192, 168, 1, 2}, 8080);
  const auto addr2 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  Hash hash;
  EXPECT_NE(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, HashDifferentIPv6) {
  const auto addr1 =
      CreateIPv6Addr({0x21, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  const auto addr2 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  Hash hash;
  EXPECT_NE(hash(addr1), hash(addr2));
}

TEST(AddrUtilsTest, AppendAndReadIPv4) {
  utils::StaticBuffer<128> buffer;
  const auto original = CreateIPv4Addr({192, 168, 1, 1}, 8080);

  Append(buffer, original);

  proto::Addr result;
  ReadAddr(buffer, result);

  EXPECT_TRUE(AddrCmp(original, result));
}

TEST(AddrUtilsTest, AppendAndReadIPv6) {
  utils::StaticBuffer<128> buffer;
  const auto original =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);

  Append(buffer, original);

  proto::Addr result;
  ReadAddr(buffer, result);

  EXPECT_TRUE(AddrCmp(original, result));
}

TEST(AddrUtilsTest, AppendAndReadDomain) {
  utils::StaticBuffer<128> buffer;
  const auto original = CreateDomainAddr("example.com", 80);

  Append(buffer, original);

  proto::Addr result;
  ReadAddr(buffer, result);

  EXPECT_TRUE(AddrCmp(original, result));
}

TEST(AddrUtilsTest, AppendAndReadMixed) {
  utils::StaticBuffer<512> buffer;
  const auto ipv4 = CreateIPv4Addr({192, 168, 1, 1}, 8080);
  const auto ipv6 =
      CreateIPv6Addr({0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00,
                      0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
                     443);
  const auto domain = CreateDomainAddr("example.com", 80);

  Append(buffer, ipv4);
  Append(buffer, ipv6);
  Append(buffer, domain);

  proto::Addr result_ipv4, result_ipv6, result_domain;
  ReadAddr(buffer, result_ipv4);
  ReadAddr(buffer, result_ipv6);
  ReadAddr(buffer, result_domain);

  EXPECT_TRUE(AddrCmp(ipv4, result_ipv4));
  EXPECT_TRUE(AddrCmp(ipv6, result_ipv6));
  EXPECT_TRUE(AddrCmp(domain, result_domain));
}

}  // namespace socks5::common
