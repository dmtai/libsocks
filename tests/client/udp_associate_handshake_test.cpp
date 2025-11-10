#include <gtest/gtest.h>
#include <client/udp_associate_handshake.hpp>
#include <net/tcp_connection.hpp>
#include <auth/client/user_auth.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/common/asio.hpp>
#include <chrono>
#include <utils/timeout.hpp>
#include <net/io.hpp>
#include <socks5/utils/buffer.hpp>
#include <common/defs.hpp>
#include <parsers/parsers.hpp>
#include <test_utils/assert_macro.hpp>
#include <common/proto_builders.hpp>
#include <serializers/serializers.hpp>
#include <socks5/utils/buffer.hpp>
#include <parsers/parsers.hpp>

namespace socks5::client {

namespace {

constexpr size_t kRequestFirst4FieldsSize{4};

class UdpAssociateHandshakeTest : public ::testing::Test {
 protected:
  UdpAssociateHandshakeTest()
      : client_acceptor_(io_context_),
        client_socket_(io_context_),
        server_socket_(io_context_) {
    client_acceptor_.open(tcp::v4());
    client_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    client_acceptor_.bind(
        tcp::endpoint{asio::ip::make_address("127.0.0.1"), 0});
    client_acceptor_.listen();
  }

  ~UdpAssociateHandshakeTest() { io_context_.stop(); }

  void ConnectClient() {
    const auto server_endpoint = client_acceptor_.local_endpoint();
    client_socket_.async_connect(server_endpoint,
                                 [](auto err) { EXPECT_FALSE(err); });
    client_acceptor_.async_accept(server_socket_,
                                  [](auto err) { EXPECT_FALSE(err); });
  }

  asio::io_context io_context_;
  tcp::acceptor client_acceptor_;
  tcp::socket client_socket_;
  tcp::socket server_socket_;
};

}  // namespace

TEST_F(UdpAssociateHandshakeTest, Run) {
  ConnectClient();
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    auth::client::AuthOptions auth_options;
    auth_options.AddAuthMethod<auth::client::AuthMethod::kNone>();
    UdpAssociateHandshake handshake{client_socket_, auth_options};

    auto handshake_future =
        asio::co_spawn(io_context_, handshake.Run(), asio::use_future);

    utils::StaticBuffer<1024> buf;
    co_await asio::async_read(server_socket_, asio::buffer(buf.BeginWrite(), 3),
                              asio::use_awaitable);
    buf.HasWritten(3);
    EXPECT_EQ(buf.Read<decltype(proto::ClientGreeting::ver)>(),
              proto::Version::kVersionVer5);
    EXPECT_EQ(buf.Read<decltype(proto::ClientGreeting::nmethods)>(), 1);
    EXPECT_EQ(buf.Read<uint8_t>(), proto::AuthMethod::kAuthMethodNone);

    const auto server_choice_buf = serializers::Serialize(
        common::MakeServerChoice(proto::AuthMethod::kAuthMethodNone));
    co_await asio::async_write(server_socket_,
                               asio::buffer(server_choice_buf.BeginRead(),
                                            server_choice_buf.ReadableBytes()),
                               asio::use_awaitable);
    RequestBuf request_buf;
    co_await asio::async_read(
        server_socket_,
        asio::buffer(request_buf.BeginWrite(),
                     kRequestFirst4FieldsSize + common::kIPv4AddrSize),
        asio::use_awaitable);
    request_buf.HasWritten(kRequestFirst4FieldsSize + common::kIPv4AddrSize);
    const auto request = parsers::ParseRequest(request_buf);

    EXPECT_EQ(request.ver, proto::Version::kVersionVer5);
    EXPECT_EQ(request.cmd, proto::RequestCmd::kRequestCmdUdpAssociate);
    EXPECT_EQ(request.rsv, 0);
    EXPECT_EQ(request.dst_addr.atyp, proto::AddrType::kAddrTypeIPv4);

    udp::endpoint ep{asio::ip::make_address("192.168.1.1"), 8080};
    const auto reply = common::MakeReply(proto::ReplyRep::kReplyRepSuccess, ep);
    const auto reply_buf = serializers::Serialize(reply);

    co_await asio::async_write(
        server_socket_,
        asio::buffer(reply_buf.BeginRead(), reply_buf.ReadableBytes()),
        asio::use_awaitable);

    co_await utils::Timeout(50);
    auto result = handshake_future.get();
    CO_ASSERT_FALSE(result.first);

    EXPECT_EQ(request.dst_addr.addr.ipv4.addr,
              (result.second->udp_socket.local_endpoint()
                   .address()
                   .to_v4()
                   .to_bytes()));
    EXPECT_EQ(asio::detail::socket_ops::network_to_host_short(
                  request.dst_addr.addr.ipv4.port),
              result.second->udp_socket.local_endpoint().port());
    EXPECT_EQ(result.second->proxy_ep, ep);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::client