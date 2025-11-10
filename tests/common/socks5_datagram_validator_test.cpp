#include <gtest/gtest.h>
#include <common/socks5_datagram_validator.hpp>
#include <socks5/utils/buffer.hpp>
#include <proto/proto.hpp>
#include <common/addr_utils.hpp>
#include <vector>

namespace socks5::common {

namespace {

template <size_t N>
void PrepareBuffer(utils::StaticBuffer<N>& buf,
                   const std::vector<uint8_t>& header,
                   const std::vector<uint8_t>& data = {}) {
  buf.Clear();
  for (const auto& b : header) {
    buf.Append(b);
  }
  for (const auto& b : data) {
    buf.Append(b);
  }
}

}  // namespace

TEST(DatagramValidatorTest, InvalidMinimalLength) {
  utils::StaticBuffer<3> buf;
  PrepareBuffer(buf, {0x00, 0x00, 0x00});  // RSV + FRAG
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, IPv4ValidWithData) {
  utils::StaticBuffer<11> buf;
  // RSV=0, FRAG=0, ATYP=IPv4, IPv4=127.0.0.1, PORT=1234, DATA='a'
  PrepareBuffer(buf,
                {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeIPv4, 127, 0, 0, 1,
                 0x04, 0xD2},
                {'a'});
  EXPECT_TRUE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, IPv4InvalidNoData) {
  utils::StaticBuffer<10> buf;
  // RSV=0, FRAG=0, ATYP=IPv4, IPv4=127.0.0.1, PORT=1234
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeIPv4, 127, 0,
                      0, 1, 0x04, 0xD2});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, IPv6ValidWithData) {
  utils::StaticBuffer<23> buf;
  // RSV=0, FRAG=0, ATYP=IPv6, IPv6=::1, PORT=1234, DATA='a'
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeIPv6,
                      0,    0,    0,    0,
                      0,    0,    0,    0,
                      0,    0,    0,    0,
                      0,    0,    0,    1,
                      0x04, 0xD2},
                {'a'});
  EXPECT_TRUE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, IPv6InvalidNoData) {
  utils::StaticBuffer<22> buf;
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeIPv6,
                      0,    0,    0,    0,
                      0,    0,    0,    0,
                      0,    0,    0,    0,
                      0,    0,    0,    1,
                      0x04, 0xD2});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, DomainValidWithData) {
  utils::StaticBuffer<64> buf;
  // RSV=0, FRAG=0, ATYP=DOMAIN, LEN=5, "hello", PORT=1234, DATA='a'
  PrepareBuffer(buf,
                {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeDomainName, 5, 'h',
                 'e', 'l', 'l', 'o', 0x04, 0xD2},
                {'a'});
  EXPECT_TRUE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, DomainInvalidNoData) {
  utils::StaticBuffer<64> buf;
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeDomainName, 5,
                      'h', 'e', 'l', 'l', 'o', 0x04, 0xD2});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, DomainInvalidShortHeader) {
  utils::StaticBuffer<4> buf;
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeDomainName});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, DomainInvalidLengthMismatch) {
  utils::StaticBuffer<8> buf;
  // Declared domain length=5 but only 3 bytes present
  PrepareBuffer(buf, {0x00, 0x00, 0x00, proto::AddrType::kAddrTypeDomainName, 5,
                      'a', 'b', 'c'});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, InvalidAddressType) {
  utils::StaticBuffer<10> buf;
  PrepareBuffer(buf, {0x00, 0x00, 0x00, 0x02,  // Invalid ATYP
                      1, 2, 3, 4, 5, 6});
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

TEST(DatagramValidatorTest, EmptyBuffer) {
  utils::StaticBuffer<0> buf;
  EXPECT_FALSE(ValidateDatagramLength(buf));
}

}  // namespace socks5::common
