#include <gtest/gtest.h>
#include <socks5/utils/buffer.hpp>
#include <parsers/parsers.hpp>
#include <proto/proto.hpp>
#include <common/addr_utils.hpp>
#include <utils/string_utils.hpp>

namespace socks5::parsers {

namespace {

template <size_t N>
utils::StaticBuffer<N> MakeBuffer(const std::vector<uint8_t>& data) {
  utils::StaticBuffer<N> buf;
  buf.Append(data.data(), data.size());
  return buf;
}

}  // namespace

TEST(ParsersTest, ParseRequestIPv4) {
  std::vector<uint8_t> data = {
      0x05,             // VER
      0x01,             // CMD (CONNECT)
      0x00,             // RSV
      0x01,             // ATYP (IPv4)
      192,  168, 1, 1,  // IP
      0x1F, 0x90        // PORT (8080)
  };

  auto buf = MakeBuffer<128>(data);
  const auto request = parsers::ParseRequest(buf);

  EXPECT_EQ(request.ver, proto::kVersionVer5);
  EXPECT_EQ(request.cmd, proto::kRequestCmdConnect);
  EXPECT_EQ(request.rsv, 0x00);
  EXPECT_EQ(request.dst_addr.atyp, proto::kAddrTypeIPv4);
  EXPECT_EQ(request.dst_addr.addr.ipv4.addr,
            (std::array<uint8_t, 4>{192, 168, 1, 1}));
  EXPECT_EQ(request.dst_addr.addr.ipv4.port, 36895);  // 8080
}

TEST(ParsersTest, ParseRequestIPv6) {
  std::vector<uint8_t> data = {
      0x05,  // VER
      0x01,  // CMD (CONNECT)
      0x00,  // RSV
      0x04,  // ATYP (IPv6)
      0,    1,   2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // IP
      0x1F, 0x90                                                  // PORT (8080)
  };

  auto buf = MakeBuffer<128>(data);
  const auto request = parsers::ParseRequest(buf);

  EXPECT_EQ(request.ver, proto::kVersionVer5);
  EXPECT_EQ(request.cmd, proto::kRequestCmdConnect);
  EXPECT_EQ(request.rsv, 0x00);
  EXPECT_EQ(request.dst_addr.atyp, proto::kAddrTypeIPv6);
  EXPECT_EQ(request.dst_addr.addr.ipv6.addr,
            (std::array<uint8_t, 16>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                     13, 14, 15}));
  EXPECT_EQ(request.dst_addr.addr.ipv6.port, 36895);  // 8080
}

TEST(ParsersTest, ParseRequestDomain) {
  std::vector<uint8_t> data = {
      0x05,                                          // VER
      0x03,                                          // CMD (UDP ASSOCIATE)
      0x00,                                          // RSV
      0x03,                                          // ATYP (DOMAIN)
      0x09,                                          // domain length
      'l',  'o', 'c', 'a', 'l', 'h', 'o', 's', 't',  // domain
      0x00, 0x50                                     // PORT (80)
  };

  auto buf = MakeBuffer<128>(data);
  const auto request = parsers::ParseRequest(buf);

  EXPECT_EQ(request.ver, proto::kVersionVer5);
  EXPECT_EQ(request.cmd, proto::kRequestCmdUdpAssociate);
  EXPECT_EQ(request.rsv, 0x00);
  EXPECT_EQ(request.dst_addr.atyp, proto::kAddrTypeDomainName);
  EXPECT_EQ(request.dst_addr.addr.domain.length, 9);
  const auto domain = utils::ToSv(request.dst_addr.addr.domain.addr,
                                  request.dst_addr.addr.domain.length);
  EXPECT_EQ(domain, "localhost");
  EXPECT_EQ(request.dst_addr.addr.domain.port, 20480);
}

TEST(ParsersTest, ParseClientGreeting) {
  std::vector<uint8_t> data = {
      0x05,       // VER
      0x02,       // NMETHODS
      0x00, 0x02  // METHODS (None, User)
  };

  auto buf = MakeBuffer<128>(data);
  const auto greeting = parsers::ParseClientGreeting(buf);

  EXPECT_EQ(greeting.ver, proto::kVersionVer5);
  EXPECT_EQ(greeting.nmethods, 2);
  EXPECT_EQ(greeting.methods[0], proto::kAuthMethodNone);
  EXPECT_EQ(greeting.methods[1], proto::kAuthMethodUser);
}

TEST(ParsersTest, ParseDatagram) {
  std::vector<uint8_t> data = {
      0x00, 0x00,                // RSV
      0x00,                      // FRAG
      0x01,                      // ATYP (IPv4)
      127,  0,    0,   1,        // IP
      0x04, 0xD2,                // PORT (1234)
      'H',  'e',  'l', 'l', 'o'  // Payload
  };

  auto buf = MakeBuffer<128>(data);
  const auto datagram = parsers::ParseDatagram(buf);

  EXPECT_EQ(datagram.header.rsv, 0);
  EXPECT_EQ(datagram.header.frag, proto::kUdpFragNoFrag);
  EXPECT_EQ(datagram.header.addr.atyp, proto::kAddrTypeIPv4);
  EXPECT_EQ(datagram.header.addr.addr.ipv4.addr,
            (std::array<uint8_t, 4>{127, 0, 0, 1}));
  EXPECT_EQ(datagram.header.addr.addr.ipv4.port, 53764);  // 1234

  EXPECT_EQ(datagram.data.data_size, 5);
  EXPECT_EQ(memcmp(datagram.data.data, "Hello", 5), 0);
}

TEST(ParsersTest, ParseUserAuthRequest) {
  std::vector<uint8_t> data = {
      0x01,                                    // VER
      0x04,                                    // ULEN
      'u',  's', 'e', 'r',                     // UNAME
      0x08,                                    // PLEN
      'p',  'a', 's', 's', 'w', 'o', 'r', 'd'  // PASSWD
  };

  auto buf = MakeBuffer<128>(data);
  const auto auth_req = parsers::ParseUserAuthRequest(buf);

  EXPECT_EQ(auth_req.ver, proto::kUserAuthVersionVer);
  EXPECT_EQ(auth_req.ulen, 4);
  const auto user = utils::ToSv(auth_req.uname, auth_req.ulen);
  const auto password = utils::ToSv(auth_req.passwd, auth_req.plen);
  EXPECT_EQ(user, "user");
  EXPECT_EQ(auth_req.plen, 8);
  EXPECT_EQ(password, "password");
}

TEST(ParsersTest, ParseServerChoice) {
  std::vector<uint8_t> data = {
      0x05,  // VER
      0x02   // METHOD (User)
  };

  auto buf = MakeBuffer<128>(data);
  const auto choice = parsers::ParseServerChoice(buf);

  EXPECT_EQ(choice.ver, proto::kVersionVer5);
  EXPECT_EQ(choice.method, proto::kAuthMethodUser);
}

TEST(ParsersTest, ParseReplyIPv6) {
  std::vector<uint8_t> data = {
      0x05,  // VER
      0x00,  // REP (Success)
      0x00,  // RSV
      0x04,  // ATYP (IPv6)
      0,    1,   2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // IPv6
      0x27, 0x0F                                                  // PORT (9999)
  };

  auto buf = MakeBuffer<128>(data);
  const auto reply = parsers::ParseReply(buf);

  EXPECT_EQ(reply.ver, proto::kVersionVer5);
  EXPECT_EQ(reply.rep, proto::kReplyRepSuccess);
  EXPECT_EQ(reply.rsv, 0x00);
  EXPECT_EQ(reply.bnd_addr.atyp, proto::kAddrTypeIPv6);
  EXPECT_EQ(reply.bnd_addr.addr.ipv6.addr,
            (std::array<uint8_t, 16>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                     13, 14, 15}));
  EXPECT_EQ(reply.bnd_addr.addr.ipv6.port, 3879);  // 9999
}

TEST(ParsersTest, ParseUserAuthResponse) {
  std::vector<uint8_t> data = {
      0x01,  // VER
      0x00   // STATUS (Success)
  };

  auto buf = MakeBuffer<128>(data);
  const auto response = parsers::ParseUserAuthResponse(buf);

  EXPECT_EQ(response.ver, proto::kUserAuthVersionVer);
  EXPECT_EQ(response.status, proto::kUserAuthStatusSuccess);
}

TEST(ParsersTest, ParseAddrIPv4) {
  std::vector<uint8_t> data = {
      0x01,             // ATYP (IPv4)
      192,  168, 1, 1,  // IP
      0x1F, 0x90        // PORT (8080)
  };

  auto buf = MakeBuffer<128>(data);
  const auto addr = parsers::ParseAddr(buf);

  EXPECT_EQ(addr.atyp, proto::kAddrTypeIPv4);
  EXPECT_EQ(addr.addr.ipv4.addr, (std::array<uint8_t, 4>{192, 168, 1, 1}));
  EXPECT_EQ(addr.addr.ipv4.port, 36895);  // 8080
}

TEST(ParsersTest, ParseAddrIPv6) {
  std::vector<uint8_t> data = {
      0x04,                                                       // ATYP (IPv6)
      0,    1,   2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // IP
      0x1F, 0x90                                                  // PORT (8080)
  };

  auto buf = MakeBuffer<128>(data);
  const auto addr = parsers::ParseAddr(buf);

  EXPECT_EQ(addr.atyp, proto::kAddrTypeIPv6);
  EXPECT_EQ(addr.addr.ipv6.addr,
            (std::array<uint8_t, 16>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                     13, 14, 15}));
  EXPECT_EQ(addr.addr.ipv6.port, 36895);  // 8080
}

TEST(ParsersTest, ParseAddrDomain) {
  std::vector<uint8_t> data = {
      0x03,                           // ATYP (DOMAIN)
      0x06,                           // length
      'g',  'o', 'o', 'g', 'l', 'e',  // domain
      0x01, 0xBB                      // PORT (443)
  };

  auto buf = MakeBuffer<128>(data);
  const auto addr = parsers::ParseAddr(buf);

  EXPECT_EQ(addr.atyp, proto::kAddrTypeDomainName);
  EXPECT_EQ(addr.addr.domain.length, 6);
  const auto domain =
      utils::ToSv(addr.addr.domain.addr, addr.addr.domain.length);
  EXPECT_EQ(domain, "google");
  EXPECT_EQ(addr.addr.domain.port, 47873);  // 443
}

TEST(ParsersTest, ParseEmptyAddr) {
  std::vector<uint8_t> data = {
      0x03,       // ATYP (DOMAIN)
      0x00,       // length (0)
      0x00, 0x00  // PORT (0)
  };

  auto buf = MakeBuffer<128>(data);
  const auto addr = parsers::ParseAddr(buf);

  EXPECT_EQ(addr.atyp, proto::kAddrTypeDomainName);
  EXPECT_EQ(addr.addr.domain.length, 0);
  EXPECT_EQ(addr.addr.domain.port, 0);
}

}  // namespace socks5::parsers
