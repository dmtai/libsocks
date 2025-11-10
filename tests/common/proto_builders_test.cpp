#include <gtest/gtest.h>
#include <common/proto_builders.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/common/address.hpp>
#include <string>
#include <common/addr_utils.hpp>

namespace socks5::common {

TEST(ProtoBuildersTest, MakeIPv4Addr) {
  const auto addr = asio::ip::make_address("192.168.0.1");
  const auto proto_addr = MakeAddr(addr, 8080);

  EXPECT_EQ(proto_addr.atyp, proto::AddrType::kAddrTypeIPv4);
  EXPECT_EQ(proto_addr.addr.ipv4.addr,
            (std::array<uint8_t, 4>{192, 168, 0, 1}));
  EXPECT_EQ(proto_addr.addr.ipv4.port,
            asio::detail::socket_ops::host_to_network_short(8080));
}

TEST(ProtoBuildersTest, MakeIPv6Addr) {
  const auto addr = asio::ip::make_address("2001:db8::1");
  const auto proto_addr = MakeAddr(addr, 443);

  EXPECT_EQ(proto_addr.atyp, proto::AddrType::kAddrTypeIPv6);
  EXPECT_EQ(proto_addr.addr.ipv6.addr,
            (std::array<uint8_t, 16>{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0x01}));
  EXPECT_EQ(proto_addr.addr.ipv6.port,
            asio::detail::socket_ops::host_to_network_short(443));
}

TEST(ProtoBuildersTest, MakeAddrDomain) {
  const auto proto_addr = MakeAddr("example.com", 80);

  EXPECT_EQ(proto_addr.atyp, proto::AddrType::kAddrTypeDomainName);
  EXPECT_EQ(proto_addr.addr.domain.length, 11);
  EXPECT_EQ((std::string_view{reinterpret_cast<const char*>(
                                  proto_addr.addr.domain.addr.data()),
                              proto_addr.addr.domain.length}),
            (std::string_view{"example.com"}));
  EXPECT_EQ(proto_addr.addr.domain.port,
            asio::detail::socket_ops::host_to_network_short(80));
}

TEST(ProtoBuildersTest, MakeUserAuthResponse) {
  const auto resp =
      MakeUserAuthResponse(proto::UserAuthStatus::kUserAuthStatusSuccess);

  EXPECT_EQ(resp.ver, proto::UserAuthVersion::kUserAuthVersionVer);
  EXPECT_EQ(resp.status, proto::UserAuthStatus::kUserAuthStatusSuccess);
}

TEST(ProtoBuildersTest, MakeUserAuthRequest) {
  auth::client::UserAuthOptions options{"user", "pass"};
  const auto req = MakeUserAuthRequest(options);

  EXPECT_EQ(req.ver, proto::UserAuthVersion::kUserAuthVersionVer);
  EXPECT_EQ(req.ulen, 4);
  EXPECT_EQ((std::string_view{reinterpret_cast<const char*>(req.uname.data()),
                              req.ulen}),
            (std::string_view{"user"}));

  EXPECT_EQ(req.plen, 4);
  EXPECT_EQ((std::string_view{reinterpret_cast<const char*>(req.passwd.data()),
                              req.plen}),
            (std::string_view{"pass"}));
}

TEST(ProtoBuildersTest, MakeClientGreeting) {
  auth::client::AuthOptions options;
  options.AddAuthMethod<auth::client::AuthMethod::kNone>();
  options.AddAuthMethod<auth::client::AuthMethod::kUser>("user1", "password1");

  const auto greeting = MakeClientGreeting(options);

  EXPECT_EQ(greeting.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(greeting.nmethods, 2);
  EXPECT_EQ(greeting.methods[0], proto::AuthMethod::kAuthMethodNone);
  EXPECT_EQ(greeting.methods[1], proto::AuthMethod::kAuthMethodUser);
}

TEST(ProtoBuildersTest, MakeReply) {
  const auto reply = MakeReply(proto::ReplyRep::kReplyRepSuccess,
                               proto::AddrType::kAddrTypeIPv4, 8080);

  EXPECT_EQ(reply.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(reply.rep, proto::ReplyRep::kReplyRepSuccess);
  EXPECT_EQ(reply.bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
  EXPECT_EQ(reply.bnd_addr.addr.ipv4.port,
            asio::detail::socket_ops::host_to_network_short(8080));
}

TEST(ProtoBuildersTest, MakeServerChoice) {
  const auto choice = MakeServerChoice(proto::AuthMethod::kAuthMethodNone);

  EXPECT_EQ(choice.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(choice.method, proto::AuthMethod::kAuthMethodNone);
}

TEST(ProtoBuildersTest, MakeReplyRep) {
  EXPECT_EQ(MakeReplyRep(asio::error::connection_refused),
            proto::ReplyRep::kReplyRepConnectionRefused);
  EXPECT_EQ(MakeReplyRep(asio::error::host_unreachable),
            proto::ReplyRep::kReplyRepHostUnreachable);
  EXPECT_EQ(MakeReplyRep(asio::error::network_unreachable),
            proto::ReplyRep::kReplyRepNetworkUnreachable);
  EXPECT_EQ(MakeReplyRep(asio::error::access_denied),
            proto::ReplyRep::kReplyRepFail);
}

TEST(ProtoBuildersTest, MakeDatagramHeader) {
  udp::endpoint ep{asio::ip::make_address("10.0.0.1"), 1234};
  const auto header = MakeDatagramHeader(ep);

  EXPECT_EQ(header.rsv, 0);
  EXPECT_EQ(header.frag, 0);
  EXPECT_EQ(header.addr.atyp, proto::AddrType::kAddrTypeIPv4);

  EXPECT_EQ(header.addr.addr.ipv4.addr, (std::array<uint8_t, 4>{10, 0, 0, 1}));
  EXPECT_EQ(header.addr.addr.ipv4.port,
            asio::detail::socket_ops::host_to_network_short(1234));
}

TEST(ProtoBuildersTest, MakeDatagram) {
  udp::endpoint ep{asio::ip::make_address("::1"), 4321};
  const char* data{"test"};
  const auto datagram = MakeDatagram(ep, data, sizeof(data));

  EXPECT_EQ(datagram.header.addr.atyp, proto::AddrType::kAddrTypeIPv6);
  EXPECT_EQ(datagram.data.data_size, sizeof(data));
  EXPECT_EQ(std::memcmp(datagram.data.data, data, std::strlen(data)), 0);
}

TEST(ProtoBuildersTest, MakeRequest) {
  Address addr{"example.com", 80};
  const auto request = MakeRequest(proto::RequestCmd::kRequestCmdConnect, addr);

  EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdConnect);
  EXPECT_EQ(request.rsv, 0);
  EXPECT_EQ(request.dst_addr.atyp, proto::AddrType::kAddrTypeDomainName);

  EXPECT_EQ((std::string_view{reinterpret_cast<const char*>(
                                  request.dst_addr.addr.domain.addr.data()),
                              request.dst_addr.addr.domain.length}),
            (std::string_view{"example.com"}));

  EXPECT_EQ(request.dst_addr.addr.domain.port,
            asio::detail::socket_ops::host_to_network_short(80));
}

TEST(ProtoBuildersTest, TemplateMakeReply) {
  tcp::endpoint ep{asio::ip::make_address("192.168.1.1"), 8080};
  const auto reply = MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);

  EXPECT_EQ(reply.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(reply.bnd_addr.atyp, proto::AddrType::kAddrTypeIPv4);
}

TEST(ProtoBuildersTest, TemplateMakeDatagram) {
  const auto addr = MakeAddr("test.com", 1234);
  constexpr std::string_view data{"buffer_data"};
  utils::StaticBuffer<1024> buf;
  buf.Append(data.data(), data.size());
  const auto datagram = MakeDatagram(addr, buf);

  EXPECT_EQ(datagram.header.addr.atyp, proto::AddrType::kAddrTypeDomainName);
  EXPECT_EQ(datagram.data.data_size, buf.ReadableBytes());

  EXPECT_TRUE(std::memcmp(datagram.data.data, buf.BeginRead(),
                          datagram.data.data_size) == 0);
  EXPECT_EQ((std::string_view{reinterpret_cast<const char*>(
                                  datagram.header.addr.addr.domain.addr.data()),
                              datagram.header.addr.addr.domain.length}),
            (std::string_view{"test.com"}));

  EXPECT_EQ(datagram.header.addr.addr.domain.port,
            asio::detail::socket_ops::host_to_network_short(1234));
}

TEST(ProtoBuildersTest, TemplateMakeRequest) {
  udp::endpoint ep{asio::ip::make_address("10.0.0.5"), 9999};
  const auto request =
      MakeRequest(proto::RequestCmd::kRequestCmdUdpAssociate, ep);

  EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
  EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdUdpAssociate);
  EXPECT_EQ(request.dst_addr.atyp, proto::AddrType::kAddrTypeIPv4);

  EXPECT_EQ(request.dst_addr.addr.ipv4.addr,
            (std::array<uint8_t, 4>{10, 0, 0, 5}));
  EXPECT_EQ(request.dst_addr.addr.ipv4.port,
            asio::detail::socket_ops::host_to_network_short(9999));
}

}  // namespace socks5::common
