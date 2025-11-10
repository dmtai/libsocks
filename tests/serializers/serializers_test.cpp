#include <gtest/gtest.h>
#include <socks5/utils/buffer.hpp>
#include <serializers/serializers.hpp>
#include <proto/proto.hpp>
#include <common/addr_utils.hpp>

namespace socks5::serializers {

namespace {

void CompareBuffer(const auto& buf, const std::vector<uint8_t>& expected) {
  ASSERT_EQ(buf.ReadableBytes(), expected.size());
  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.BeginRead());
  for (size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(data[i], expected[i]) << "Mismatch at byte " << i;
  }
}

}  // namespace

TEST(SerializersTest, SerializeServerChoice) {
  proto::ServerChoice sc;
  sc.ver = proto::kVersionVer5;
  sc.method = proto::kAuthMethodNone;

  const auto buf = Serialize(sc);
  const std::vector<uint8_t> expected{0x05, 0x00};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeReplyIPv4) {
  proto::Reply reply;
  reply.ver = proto::kVersionVer5;
  reply.rep = proto::kReplyRepSuccess;
  reply.rsv = 0x00;
  reply.bnd_addr.atyp = proto::kAddrTypeIPv4;
  reply.bnd_addr.addr.ipv4 = {{192, 168, 1, 1}, htons(8080)};

  const auto buf = Serialize(reply);
  const std::vector<uint8_t> expected{0x05, 0x00, 0x00, 0x01, 192,
                                      168,  1,    1,    0x1F, 0x90};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeReplyDomain) {
  proto::Reply reply;
  reply.ver = proto::kVersionVer5;
  reply.rep = proto::kReplyRepSuccess;
  reply.rsv = 0x00;
  reply.bnd_addr.atyp = proto::kAddrTypeDomainName;
  reply.bnd_addr.addr.domain.length = 9;
  memcpy(reply.bnd_addr.addr.domain.addr.data(), "localhost", 9);
  reply.bnd_addr.addr.domain.port = htons(80);

  const auto buf = Serialize(reply);
  const std::vector<uint8_t> expected{0x05, 0x00, 0x00, 0x03, 0x09, 'l',
                                      'o',  'c',  'a',  'l',  'h',  'o',
                                      's',  't',  0x00, 0x50};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeUserAuthResponse) {
  proto::UserAuthResponse uar;
  uar.ver = proto::kUserAuthVersionVer;
  uar.status = proto::kUserAuthStatusSuccess;

  const auto buf = Serialize(uar);
  const std::vector<uint8_t> expected{0x01, 0x00};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeClientGreeting) {
  proto::ClientGreeting cg;
  cg.ver = proto::kVersionVer5;
  cg.nmethods = 3;
  cg.methods = {proto::kAuthMethodNone, proto::kAuthMethodUser,
                proto::kAuthMethodGSSAPI};

  const auto buf = Serialize(cg);
  const std::vector<uint8_t> expected{0x05, 0x03, 0x00, 0x02, 0x01};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeRequestIPv6) {
  proto::Request req;
  req.ver = proto::kVersionVer5;
  req.cmd = proto::kRequestCmdUdpAssociate;
  req.rsv = 0x00;
  req.dst_addr.atyp = proto::kAddrTypeIPv6;
  req.dst_addr.addr.ipv6 = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, htons(9999)};

  const auto buf = Serialize(req);
  const std::vector<uint8_t> expected{0x05, 0x03, 0x00, 0x04, 0,    1,   2,  3,
                                      4,    5,    6,    7,    8,    9,   10, 11,
                                      12,   13,   14,   15,   0x27, 0x0F};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeUserAuthRequest) {
  proto::UserAuthRequest uar;
  uar.ver = proto::kUserAuthVersionVer;
  uar.ulen = 4;
  memcpy(uar.uname.data(), "user", 4);
  uar.plen = 8;
  memcpy(uar.passwd.data(), "password", 8);

  const auto buf = Serialize(uar);
  const std::vector<uint8_t> expected{0x01, 0x04, 'u', 's', 'e', 'r', 0x08, 'p',
                                      'a',  's',  's', 'w', 'o', 'r', 'd'};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeDatagramHeader) {
  proto::DatagramHeader dh;
  dh.rsv = 0;
  dh.frag = proto::kUdpFragNoFrag;
  dh.addr.atyp = proto::kAddrTypeDomainName;
  dh.addr.addr.domain.length = 4;
  memcpy(dh.addr.addr.domain.addr.data(), "test", 4);
  dh.addr.addr.domain.port = htons(12345);

  const auto buf = Serialize(dh);
  const std::vector<uint8_t> expected{
      0x00, 0x00,                       // rsv
      0x00,                             // frag
      0x03,                             // atyp (domain)
      0x04,                             // len
      't',  'e',  's', 't', 0x30, 0x39  // 12345
  };
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeAddrIPv4) {
  proto::Addr addr;
  addr.atyp = proto::kAddrTypeIPv4;
  addr.addr.ipv4 = {{8, 8, 4, 4}, htons(53)};

  const auto buf = Serialize(addr);
  const std::vector<uint8_t> expected{
      0x01,             // IPv4
      8,    8,   4, 4,  // IP
      0x00, 0x35        // 53
  };
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeAddrIPv6) {
  proto::Addr addr;
  addr.atyp = proto::kAddrTypeIPv6;
  addr.addr.ipv6 = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                    htons(9999)};

  const auto buf = Serialize(addr);
  const std::vector<uint8_t> expected{
      0x04, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x27, 0x0F};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeAddrDomain) {
  proto::Addr addr;
  addr.atyp = proto::kAddrTypeDomainName;
  addr.addr.domain.length = 9;
  memcpy(addr.addr.domain.addr.data(), "localhost", 9);
  addr.addr.domain.port = htons(80);

  const auto buf = Serialize(addr);
  const std::vector<uint8_t> expected{0x03, 0x09, 'l', 'o', 'c',  'a', 'l',
                                      'h',  'o',  's', 't', 0x00, 0x50};
  CompareBuffer(buf, expected);
}

TEST(SerializersTest, SerializeAddrEmptyDomain) {
  proto::Addr addr;
  addr.atyp = proto::kAddrTypeDomainName;
  addr.addr.domain.length = 0;
  addr.addr.domain.port = 0;

  const auto buf = Serialize(addr);
  const std::vector<uint8_t> expected{
      0x03,       // Domain
      0x00,       // Length
      0x00, 0x00  // Port
  };
  CompareBuffer(buf, expected);
}

}  // namespace socks5::serializers
