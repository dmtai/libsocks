#include <gtest/gtest.h>
#include <server/udp_relay.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/metrics.hpp>
#include <test_utils/assert_macro.hpp>
#include <server/relay_data_processors.hpp>
#include <net/udp_connection.hpp>
#include <socks5/utils/watchdog.hpp>
#include <common/proto_builders.hpp>
#include <serializers/serializers.hpp>
#include <common/socks5_datagram_io.hpp>
#include <socks5/utils/buffer.hpp>
#include <parsers/parsers.hpp>
#include <chrono>

namespace socks5::server {

namespace {

class UdpRelayTest : public testing::Test {
 protected:
  UdpRelayTest()
      : tcp_acceptor_{io_context_},
        client_tcp_socket_{io_context_},
        proxy_tcp_socket_{io_context_},
        proxy_udp_socket_ep_{asio::ip::address::from_string("127.0.0.1"), 7777},
        proxy_udp_socket_{io_context_, proxy_udp_socket_ep_},
        client_udp_socket_ep_{asio::ip::address::from_string("127.0.0.1"),
                              12345},
        client_udp_socket_{io_context_, client_udp_socket_ep_},
        server_udp_socket_ep_{asio::ip::address::from_string("127.0.0.1"),
                              12346},
        server_udp_socket_{io_context_, server_udp_socket_ep_} {
    tcp_acceptor_.open(tcp::v4());
    tcp_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    tcp_acceptor_.bind(tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    tcp_acceptor_.listen();

    client_udp_socket_addr_ = common::MakeAddr(client_udp_socket_ep_.address(),
                                               client_udp_socket_ep_.port());
    server_udp_socket_addr_ = common::MakeAddr(server_udp_socket_ep_.address(),
                                               server_udp_socket_ep_.port());
    server_udp_socket_addr_buf_ =
        serializers::Serialize(server_udp_socket_addr_);
  }

  void MakeSockets() {
    const auto server_endpoint = tcp_acceptor_.local_endpoint();
    client_tcp_socket_.async_connect(server_endpoint, [](auto) {});
    tcp_acceptor_.accept(proxy_tcp_socket_);
  }

  asio::io_context io_context_;
  tcp::acceptor tcp_acceptor_;
  tcp::socket client_tcp_socket_;
  tcp::socket proxy_tcp_socket_;
  udp::endpoint proxy_udp_socket_ep_;
  udp::socket proxy_udp_socket_;
  udp::endpoint client_udp_socket_ep_;
  udp::socket client_udp_socket_;
  udp::endpoint server_udp_socket_ep_;
  udp::socket server_udp_socket_;
  proto::Addr client_udp_socket_addr_;
  proto::Addr server_udp_socket_addr_;
  AddrBuf server_udp_socket_addr_buf_;
  common::Metrics metrics_;
};

void TestUdpRelayHandlerCb(asio::io_context& io_context, tcp::socket client,
                           udp::socket proxy, common::Address address,
                           const Config& config, common::Metrics& metrics) {
  auto proxy_ptr = std::make_shared<udp::socket>(std::move(proxy));
  auto sender_ep_ptr = std::make_shared<udp::endpoint>();
  auto data_ptr = std::make_shared<std::array<char, 1024>>();
  proxy_ptr->async_receive_from(
      asio::buffer(data_ptr->data(), data_ptr->size()), *sender_ep_ptr,
      [proxy_ptr, sender_ep_ptr, data_ptr](const boost::system::error_code& ec,
                                           size_t n) {
        if (!ec) {
          proxy_ptr->async_send_to(
              asio::buffer("ok"), *sender_ep_ptr,
              [](const boost::system::error_code&, size_t) {});
        }
      });
}

VoidAwait CoroTestUdpRelayHandlerCb(asio::io_context& io_context,
                                    tcp::socket client, udp::socket proxy,
                                    common::Address address,
                                    const Config& config,
                                    common::Metrics& metrics) {
  std::array<char, 1024> data;
  udp::endpoint sender_ep;
  co_await proxy.async_receive_from(asio::buffer(data.data(), data.size()),
                                    sender_ep, asio::use_awaitable);
  co_await proxy.async_send_to(asio::buffer("ok"), sender_ep,
                               asio::use_awaitable);
}

}  // namespace

TEST_F(UdpRelayTest, DefaultUdpRelayHandlerBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       DefaultUdpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    asio::co_spawn(io_context_, udp_relay.Run(), asio::detached);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(data.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(data, buf);

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data2.data(), data2.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm =
        common::MakeDatagram(server_udp_socket_ep_, data2.data(), data2.size());
    utils::StaticBuffer<kDatagramMaxLen> buf2;
    udp::endpoint sender_ep2;
    const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
        asio::use_awaitable);
    buf2.HasWritten(recv_bytes);
    const auto dgrm2 = parsers::ParseDatagram(buf2);
    EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                            dgrm2.data.data_size) == 0);
    EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

    const std::vector<char> data3{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    const auto dgrm_buffs2 = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data3.data(), data3.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs2, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf3(data3.size());
    udp::endpoint sender_ep3;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf3.data(), buf3.size()), sender_ep3,
        asio::use_awaitable);
    EXPECT_EQ(data3, buf3);

    const std::vector<char> data4{'t', 'e', 's', 't', 'm', 's', 'g', '3'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data4.data(), data4.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm2 =
        common::MakeDatagram(server_udp_socket_ep_, data4.data(), data4.size());
    utils::StaticBuffer<kDatagramMaxLen> buf4;
    udp::endpoint sender_ep4;
    const auto recv_bytes2 = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf4.BeginWrite(), buf4.WritableBytes()), sender_ep4,
        asio::use_awaitable);
    buf4.HasWritten(recv_bytes2);
    const auto dgrm3 = parsers::ParseDatagram(buf4);
    EXPECT_EQ(dgrm3.header.rsv, expected_dgrm2.header.rsv);
    EXPECT_EQ(dgrm3.header.frag, expected_dgrm2.header.frag);
    EXPECT_EQ(dgrm3.header.addr.addr.ipv4.addr,
              expected_dgrm2.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm3.header.addr.addr.ipv4.port,
              expected_dgrm2.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm3.data.data_size, expected_dgrm2.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm3.data.data, expected_dgrm2.data.data,
                            dgrm3.data.data_size) == 0);
    EXPECT_EQ(sender_ep4, proxy_udp_socket_ep_);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, DefaultUdpRelayHandlerMultipleTargetServersRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       DefaultUdpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    asio::co_spawn(io_context_, udp_relay.Run(), asio::detached);

    std::vector<udp::socket> server_sockets;
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12348}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12349}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12350}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12351}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12352}});

    for (int i = 0; i < 10; ++i) {
      for (auto& server_socket : server_sockets) {
        auto server_socket_ep = server_socket.local_endpoint();
        auto server_socket_addr = common::MakeAddr(server_socket_ep.address(),
                                                   server_socket_ep.port());
        auto server_socket_addr_buf =
            serializers::Serialize(server_socket_addr);

        const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
        const auto dgrm_buffs = common::MakeDatagramBuffs(
            server_socket_addr_buf, data.data(), data.size());
        co_await client_udp_socket_.async_send_to(
            dgrm_buffs, proxy_udp_socket_ep_, asio::use_awaitable);
        std::vector<char> buf(data.size());
        udp::endpoint sender_ep;
        co_await server_socket.async_receive_from(
            asio::buffer(buf.data(), buf.size()), sender_ep,
            asio::use_awaitable);
        EXPECT_EQ(data, buf);

        const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
        co_await server_socket.async_send_to(
            asio::buffer(data2.data(), data2.size()), sender_ep,
            asio::use_awaitable);
        const auto expected_dgrm =
            common::MakeDatagram(server_socket_ep, data2.data(), data2.size());
        utils::StaticBuffer<kDatagramMaxLen> buf2;
        udp::endpoint sender_ep2;
        const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
            asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
            asio::use_awaitable);
        buf2.HasWritten(recv_bytes);
        const auto dgrm2 = parsers::ParseDatagram(buf2);
        EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
        EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
                  expected_dgrm.header.addr.addr.ipv4.addr);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
                  expected_dgrm.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
                  expected_dgrm.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
        EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                                dgrm2.data.data_size) == 0);
        EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

        const std::vector<char> data3{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
        const auto dgrm_buffs2 = common::MakeDatagramBuffs(
            server_socket_addr_buf, data3.data(), data3.size());
        co_await client_udp_socket_.async_send_to(
            dgrm_buffs2, proxy_udp_socket_ep_, asio::use_awaitable);
        std::vector<char> buf3(data3.size());
        udp::endpoint sender_ep3;
        co_await server_socket.async_receive_from(
            asio::buffer(buf3.data(), buf3.size()), sender_ep3,
            asio::use_awaitable);
        EXPECT_EQ(data3, buf3);

        const std::vector<char> data4{'t', 'e', 's', 't', 'm', 's', 'g', '3'};
        co_await server_socket.async_send_to(
            asio::buffer(data4.data(), data4.size()), sender_ep,
            asio::use_awaitable);
        const auto expected_dgrm2 =
            common::MakeDatagram(server_socket_ep, data4.data(), data4.size());
        utils::StaticBuffer<kDatagramMaxLen> buf4;
        udp::endpoint sender_ep4;
        const auto recv_bytes2 = co_await client_udp_socket_.async_receive_from(
            asio::buffer(buf4.BeginWrite(), buf4.WritableBytes()), sender_ep4,
            asio::use_awaitable);
        buf4.HasWritten(recv_bytes2);
        const auto dgrm3 = parsers::ParseDatagram(buf4);
        EXPECT_EQ(dgrm3.header.rsv, expected_dgrm2.header.rsv);
        EXPECT_EQ(dgrm3.header.frag, expected_dgrm2.header.frag);
        EXPECT_EQ(dgrm3.header.addr.addr.ipv4.addr,
                  expected_dgrm2.header.addr.addr.ipv4.addr);
        EXPECT_EQ(dgrm3.header.addr.addr.ipv4.port,
                  expected_dgrm2.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm3.data.data_size, expected_dgrm2.data.data_size);
        EXPECT_TRUE(std::memcmp(dgrm3.data.data, expected_dgrm2.data.data,
                                dgrm3.data.data_size) == 0);
        EXPECT_EQ(sender_ep4, proxy_udp_socket_ep_);
      }
    }

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, DefaultUdpRelayHandlerCloseTcpConnect) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       DefaultUdpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(data.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(data, buf);

    client_tcp_socket_.shutdown(tcp::socket::shutdown_both);
    client_tcp_socket_.close();

    co_await utils::Timeout(100);
    auto res = fut.wait_for(std::chrono::milliseconds{1});
    EXPECT_EQ(res, std::future_status::ready);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, DefaultUdpRelayHandlerTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    config.udp_relay_timeout = 1;
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       DefaultUdpRelayHandler,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(data.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(data, buf);

    co_await utils::Timeout(1100);
    auto res = fut.wait_for(std::chrono::milliseconds{1});
    EXPECT_EQ(res, std::future_status::ready);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, UppRelayHandlerWithDataProcessorBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    std::string_view processed_testmsg1{"processed_testmsg1"};
    const auto client_to_server = [&](const udp::endpoint& client) {
      return [&](const char* data, size_t size, const udp::endpoint& server,
                 const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg1"}));
        send(processed_testmsg1.data(), processed_testmsg1.size());
      };
    };

    std::string_view processed_testmsg2{"processed_testmsg2"};
    const auto server_to_client = [&](const udp::endpoint& client,
                                      const udp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg2"}));
        send(processed_testmsg2.data(), processed_testmsg2.size());
      };
    };

    UdpRelayDataProcessor udp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       UdpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       udp_relay_data_processor};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(processed_testmsg1.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(processed_testmsg1, (std::string_view{buf.data(), buf.size()}));

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data2.data(), data2.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm =
        common::MakeDatagram(server_udp_socket_ep_, processed_testmsg2.data(),
                             processed_testmsg2.size());
    utils::StaticBuffer<kDatagramMaxLen> buf2;
    udp::endpoint sender_ep2;
    const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
        asio::use_awaitable);
    buf2.HasWritten(recv_bytes);
    const auto dgrm2 = parsers::ParseDatagram(buf2);
    EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                            dgrm2.data.data_size) == 0);
    EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest,
       UdpRelayHandlerWithDataProcessorMultipleDataTransmissions) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    bool client_to_server_processed{false};
    const auto client_to_server = [&](const udp::endpoint& client) {
      return [&](const char* data, size_t size, const udp::endpoint& server,
                 const RelayDataSender& send) {
        client_to_server_processed = true;
        send(data, size);
        send(data, size);
      };
    };

    bool server_to_client_processed{false};
    const auto server_to_client = [&](const udp::endpoint& client,
                                      const udp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        server_to_client_processed = true;
        send(data, size);
        send(data, size);
      };
    };

    UdpRelayDataProcessor udp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       UdpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       udp_relay_data_processor};

    asio::co_spawn(io_context_, udp_relay.Run(), asio::detached);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(data.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_TRUE(client_to_server_processed);
    EXPECT_EQ(buf, data);

    std::vector<char> buf2(data.size());
    udp::endpoint sender_ep2;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf2.data(), buf2.size()), sender_ep2,
        asio::use_awaitable);
    EXPECT_EQ(buf2, data);

    const std::vector<char> data3{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data3.data(), data3.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm =
        common::MakeDatagram(server_udp_socket_ep_, data3.data(), data3.size());
    utils::StaticBuffer<kDatagramMaxLen> buf3;
    udp::endpoint sender_ep3;
    const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf3.BeginWrite(), buf3.WritableBytes()), sender_ep3,
        asio::use_awaitable);
    buf3.HasWritten(recv_bytes);
    const auto dgrm2 = parsers::ParseDatagram(buf3);
    EXPECT_TRUE(server_to_client_processed);
    EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                            dgrm2.data.data_size) == 0);
    EXPECT_EQ(sender_ep3, proxy_udp_socket_ep_);

    utils::StaticBuffer<kDatagramMaxLen> buf4;
    udp::endpoint sender_ep4;
    const auto recv_bytes2 = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf4.BeginWrite(), buf4.WritableBytes()), sender_ep4,
        asio::use_awaitable);
    buf4.HasWritten(recv_bytes2);
    const auto dgrm3 = parsers::ParseDatagram(buf4);
    EXPECT_EQ(dgrm3.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm3.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm3.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm3.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm3.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm3.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm3.data.data, expected_dgrm.data.data,
                            dgrm3.data.data_size) == 0);
    EXPECT_EQ(sender_ep4, proxy_udp_socket_ep_);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest,
       UdpRelayHandlerWithDataProcessorMultipleTargetServersRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    bool client_to_server_processed{false};
    const auto client_to_server = [&](const udp::endpoint& client) {
      return [&](const char* data, size_t size, const udp::endpoint& server,
                 const RelayDataSender& send) {
        client_to_server_processed = true;
        send(data, size);
      };
    };

    bool server_to_client_processed{false};
    const auto server_to_client = [&](const udp::endpoint& client,
                                      const udp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        server_to_client_processed = true;
        send(data, size);
      };
    };

    UdpRelayDataProcessor udp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       UdpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       udp_relay_data_processor};

    asio::co_spawn(io_context_, udp_relay.Run(), asio::detached);

    std::vector<udp::socket> server_sockets;
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12348}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12349}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12350}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12351}});
    server_sockets.push_back(udp::socket{
        io_context_,
        udp::endpoint{asio::ip::address::from_string("127.0.0.1"), 12352}});

    for (int i = 0; i < 10; ++i) {
      for (auto& server_socket : server_sockets) {
        auto server_socket_ep = server_socket.local_endpoint();
        auto server_socket_addr = common::MakeAddr(server_socket_ep.address(),
                                                   server_socket_ep.port());
        auto server_socket_addr_buf =
            serializers::Serialize(server_socket_addr);

        const std::vector<char> data{'h', 'e', 'l', 'l', 'o'};
        const auto dgrm_buffs = common::MakeDatagramBuffs(
            server_socket_addr_buf, data.data(), data.size());
        co_await client_udp_socket_.async_send_to(
            dgrm_buffs, proxy_udp_socket_ep_, asio::use_awaitable);
        std::vector<char> buf(data.size());
        udp::endpoint sender_ep;
        co_await server_socket.async_receive_from(
            asio::buffer(buf.data(), buf.size()), sender_ep,
            asio::use_awaitable);
        EXPECT_TRUE(client_to_server_processed);
        EXPECT_EQ(data, buf);

        const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
        co_await server_socket.async_send_to(
            asio::buffer(data2.data(), data2.size()), sender_ep,
            asio::use_awaitable);
        const auto expected_dgrm =
            common::MakeDatagram(server_socket_ep, data2.data(), data2.size());
        utils::StaticBuffer<kDatagramMaxLen> buf2;
        udp::endpoint sender_ep2;
        const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
            asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
            asio::use_awaitable);
        buf2.HasWritten(recv_bytes);
        const auto dgrm2 = parsers::ParseDatagram(buf2);
        EXPECT_TRUE(server_to_client_processed);
        EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
        EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
                  expected_dgrm.header.addr.addr.ipv4.addr);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
                  expected_dgrm.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
                  expected_dgrm.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
        EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                                dgrm2.data.data_size) == 0);
        EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

        const std::vector<char> data3{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
        const auto dgrm_buffs2 = common::MakeDatagramBuffs(
            server_socket_addr_buf, data3.data(), data3.size());
        co_await client_udp_socket_.async_send_to(
            dgrm_buffs2, proxy_udp_socket_ep_, asio::use_awaitable);
        std::vector<char> buf3(data3.size());
        udp::endpoint sender_ep3;
        co_await server_socket.async_receive_from(
            asio::buffer(buf3.data(), buf3.size()), sender_ep3,
            asio::use_awaitable);
        EXPECT_EQ(data3, buf3);

        const std::vector<char> data4{'t', 'e', 's', 't', 'm', 's', 'g', '3'};
        co_await server_socket.async_send_to(
            asio::buffer(data4.data(), data4.size()), sender_ep,
            asio::use_awaitable);
        const auto expected_dgrm2 =
            common::MakeDatagram(server_socket_ep, data4.data(), data4.size());
        utils::StaticBuffer<kDatagramMaxLen> buf4;
        udp::endpoint sender_ep4;
        const auto recv_bytes2 = co_await client_udp_socket_.async_receive_from(
            asio::buffer(buf4.BeginWrite(), buf4.WritableBytes()), sender_ep4,
            asio::use_awaitable);
        buf4.HasWritten(recv_bytes2);
        const auto dgrm3 = parsers::ParseDatagram(buf4);
        EXPECT_EQ(dgrm3.header.rsv, expected_dgrm2.header.rsv);
        EXPECT_EQ(dgrm3.header.frag, expected_dgrm2.header.frag);
        EXPECT_EQ(dgrm3.header.addr.addr.ipv4.addr,
                  expected_dgrm2.header.addr.addr.ipv4.addr);
        EXPECT_EQ(dgrm3.header.addr.addr.ipv4.port,
                  expected_dgrm2.header.addr.addr.ipv4.port);
        EXPECT_EQ(dgrm3.data.data_size, expected_dgrm2.data.data_size);
        EXPECT_TRUE(std::memcmp(dgrm3.data.data, expected_dgrm2.data.data,
                                dgrm3.data.data_size) == 0);
        EXPECT_EQ(sender_ep4, proxy_udp_socket_ep_);
      }
    }

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, UppRelayHandlerWithDataProcessorTimeout) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    std::string_view processed_testmsg1{"processed_testmsg1"};
    const auto client_to_server = [&](const udp::endpoint& client) {
      return [&](const char* data, size_t size, const udp::endpoint& server,
                 const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg1"}));
        send(processed_testmsg1.data(), processed_testmsg1.size());
      };
    };

    std::string_view processed_testmsg2{"processed_testmsg2"};
    const auto server_to_client = [&](const udp::endpoint& client,
                                      const udp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg2"}));
        send(processed_testmsg2.data(), processed_testmsg2.size());
      };
    };

    UdpRelayDataProcessor udp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    config.udp_relay_timeout = 1;
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       UdpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       udp_relay_data_processor};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(processed_testmsg1.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(processed_testmsg1, (std::string_view{buf.data(), buf.size()}));

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data2.data(), data2.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm =
        common::MakeDatagram(server_udp_socket_ep_, processed_testmsg2.data(),
                             processed_testmsg2.size());
    utils::StaticBuffer<kDatagramMaxLen> buf2;
    udp::endpoint sender_ep2;
    const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
        asio::use_awaitable);
    buf2.HasWritten(recv_bytes);
    const auto dgrm2 = parsers::ParseDatagram(buf2);
    EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                            dgrm2.data.data_size) == 0);
    EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

    co_await utils::Timeout(1100);
    auto res = fut.wait_for(std::chrono::milliseconds{1});
    EXPECT_EQ(res, std::future_status::ready);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, UppRelayHandlerWithDataProcessorCloseTcpConnect) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    std::string_view processed_testmsg1{"processed_testmsg1"};
    const auto client_to_server = [&](const udp::endpoint& client) {
      return [&](const char* data, size_t size, const udp::endpoint& server,
                 const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg1"}));
        send(processed_testmsg1.data(), processed_testmsg1.size());
      };
    };

    std::string_view processed_testmsg2{"processed_testmsg2"};
    const auto server_to_client = [&](const udp::endpoint& client,
                                      const udp::endpoint& server) {
      return [&](const char* data, size_t size, const RelayDataSender& send) {
        EXPECT_EQ((std::string_view{data, size}),
                  (std::string_view{"testmsg2"}));
        send(processed_testmsg2.data(), processed_testmsg2.size());
      };
    };

    UdpRelayDataProcessor udp_relay_data_processor{client_to_server,
                                                   server_to_client};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       UdpRelayHandlerWithDataProcessor,
                       config,
                       metrics_,
                       udp_relay_data_processor};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(processed_testmsg1.size());
    udp::endpoint sender_ep;
    co_await server_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ(processed_testmsg1, (std::string_view{buf.data(), buf.size()}));

    const std::vector<char> data2{'t', 'e', 's', 't', 'm', 's', 'g', '2'};
    co_await server_udp_socket_.async_send_to(
        asio::buffer(data2.data(), data2.size()), sender_ep,
        asio::use_awaitable);
    const auto expected_dgrm =
        common::MakeDatagram(server_udp_socket_ep_, processed_testmsg2.data(),
                             processed_testmsg2.size());
    utils::StaticBuffer<kDatagramMaxLen> buf2;
    udp::endpoint sender_ep2;
    const auto recv_bytes = co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf2.BeginWrite(), buf2.WritableBytes()), sender_ep2,
        asio::use_awaitable);
    buf2.HasWritten(recv_bytes);
    const auto dgrm2 = parsers::ParseDatagram(buf2);
    EXPECT_EQ(dgrm2.header.rsv, expected_dgrm.header.rsv);
    EXPECT_EQ(dgrm2.header.frag, expected_dgrm.header.frag);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.addr,
              expected_dgrm.header.addr.addr.ipv4.addr);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.header.addr.addr.ipv4.port,
              expected_dgrm.header.addr.addr.ipv4.port);
    EXPECT_EQ(dgrm2.data.data_size, expected_dgrm.data.data_size);
    EXPECT_TRUE(std::memcmp(dgrm2.data.data, expected_dgrm.data.data,
                            dgrm2.data.data_size) == 0);
    EXPECT_EQ(sender_ep2, proxy_udp_socket_ep_);

    client_tcp_socket_.shutdown(tcp::socket::shutdown_both);
    client_tcp_socket_.close();

    co_await utils::Timeout(100);
    auto res = fut.wait_for(std::chrono::milliseconds{1});
    EXPECT_EQ(res, std::future_status::ready);

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, UdpRelayHandlerCbBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       TestUdpRelayHandlerCb,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(2);
    udp::endpoint sender_ep;
    co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ((std::string_view{"ok"}),
              (std::string_view{buf.data(), buf.size()}));

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{50000000});
  EXPECT_TRUE(completed);
}

TEST_F(UdpRelayTest, CoroUdpRelayHandlerCbBasicRelay) {
  bool completed{false};
  auto main = [&]() -> asio::awaitable<void> {
    MakeSockets();

    net::TcpConnection client_connect{std::move(proxy_tcp_socket_), metrics_};
    net::UdpConnection proxy_connect{std::move(proxy_udp_socket_), metrics_};

    Config config{};
    UdpRelay udp_relay{io_context_,
                       std::move(client_connect),
                       std::move(proxy_connect),
                       client_udp_socket_addr_,
                       CoroTestUdpRelayHandlerCb,
                       config,
                       metrics_,
                       MakeDefaultUdpRelayDataProcessor()};

    auto fut = asio::co_spawn(io_context_, udp_relay.Run(), asio::use_future);

    const std::vector<char> data{'t', 'e', 's', 't', 'm', 's', 'g', '1'};
    const auto dgrm_buffs = common::MakeDatagramBuffs(
        server_udp_socket_addr_buf_, data.data(), data.size());
    co_await client_udp_socket_.async_send_to(dgrm_buffs, proxy_udp_socket_ep_,
                                              asio::use_awaitable);
    std::vector<char> buf(2);
    udp::endpoint sender_ep;
    co_await client_udp_socket_.async_receive_from(
        asio::buffer(buf.data(), buf.size()), sender_ep, asio::use_awaitable);
    EXPECT_EQ((std::string_view{"ok"}),
              (std::string_view{buf.data(), buf.size()}));

    io_context_.stop();
    completed = true;
  };

  asio::co_spawn(io_context_, main, asio::detached);
  io_context_.run_for(std::chrono::seconds{5});
  EXPECT_TRUE(completed);
}

}  // namespace socks5::server