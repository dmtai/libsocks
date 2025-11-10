#pragma once

#include <server/handshake.hpp>
#include <server/tcp_relay.hpp>
#include <utils/logger.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <net/utils.hpp>
#include <server/udp_relay.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/server/config.hpp>

namespace socks5::server {

template <typename TcpRelay, typename UdpRelay, typename Handshake>
class Proxy final : utils::NonCopyable {
 public:
  using TcpRelayHandler = TcpRelay::RelayHandler;
  using UdpRelayHandler = UdpRelay::RelayHandler;

  Proxy(asio::io_context& io_context, net::TcpConnection connect,
        const TcpRelayHandler& tcp_relay_handler,
        const UdpRelayHandler& udp_relay_handler, const Config& config,
        common::Metrics& metrics, const auth::server::UserAuthCb& user_auth_cb,
        const TcpRelayDataProcessor& tcp_data_processor,
        const UdpRelayDataProcessor& udp_data_processor) noexcept
      : io_context_{io_context},
        connect_{std::move(connect)},
        tcp_relay_handler_{tcp_relay_handler},
        udp_relay_handler_{udp_relay_handler},
        config_{config},
        metrics_{metrics},
        user_auth_cb_{user_auth_cb},
        tcp_relay_data_processor_{tcp_data_processor},
        udp_relay_data_processor_{udp_data_processor} {}

  VoidAwait Run() noexcept {
    try {
      Handshake handshake{connect_, config_, user_auth_cb_};
      auto handshake_res = co_await handshake.Run();
      if (!handshake_res) {
        SOCKS5_LOG(debug, "Handshake failure. Client: {}",
                   net::ToString(connect_));
        co_return connect_.Stop();
      }
      co_await Relay(*handshake_res);
    } catch (const std::exception& ex) {
      SOCKS5_LOG(error, "Proxy exception. {}", ex.what());
    }
  }

 private:
  VoidAwait Relay(HandshakeResult& handshake_res) {
    co_await std::visit(
        [this](auto& cmd_result) -> VoidAwait {
          co_await RunRelay(cmd_result);
        },
        handshake_res);
  }

  VoidAwait RunRelay(ConnectCmdResult& connect_cmd_res) noexcept {
    TcpRelay tcp_relay{
        io_context_,
        std::move(connect_),
        net::MakeTcpConnect(std::move(connect_cmd_res.socket), metrics_),
        tcp_relay_handler_,
        config_,
        metrics_,
        tcp_relay_data_processor_};
    co_await tcp_relay.Run();
  }

  VoidAwait RunRelay(UdpAssociateCmdResult& udp_associate_cmd_res) noexcept {
    UdpRelay udp_relay{
        io_context_,
        std::move(connect_),
        net::MakeUdpConnect(std::move(udp_associate_cmd_res.proxy_socket),
                            metrics_),
        std::move(udp_associate_cmd_res.client_addr),
        udp_relay_handler_,
        config_,
        metrics_,
        udp_relay_data_processor_};
    co_await udp_relay.Run();
  }

  VoidAwait RunRelay(BindCmdResult& bind_cmd_res) noexcept {
    TcpRelay tcp_relay{
        io_context_,
        std::move(connect_),
        net::MakeTcpConnect(std::move(bind_cmd_res.socket), metrics_),
        tcp_relay_handler_,
        config_,
        metrics_,
        tcp_relay_data_processor_};
    co_await tcp_relay.Run();
  }

  asio::io_context& io_context_;
  net::TcpConnection connect_;
  const TcpRelayHandler& tcp_relay_handler_;
  const UdpRelayHandler& udp_relay_handler_;
  const Config& config_;
  common::Metrics& metrics_;
  const auth::server::UserAuthCb& user_auth_cb_;
  const TcpRelayDataProcessor& tcp_relay_data_processor_;
  const UdpRelayDataProcessor& udp_relay_data_processor_;
};

template <typename Proxy>
VoidAwait RunProxy(asio::io_context& io_context, tcp::socket socket,
                   const typename Proxy::TcpRelayHandler& tcp_relay,
                   const typename Proxy::UdpRelayHandler& udp_relay,
                   const Config& config, common::Metrics& metrics,
                   const auth::server::UserAuthCb& user_auth_cb,
                   const TcpRelayDataProcessor& tcp_data_processor,
                   const UdpRelayDataProcessor& udp_data_processor) noexcept {
  Proxy proxy{io_context,
              net::MakeTcpConnect(std::move(socket), metrics),
              tcp_relay,
              udp_relay,
              config,
              metrics,
              user_auth_cb,
              tcp_data_processor,
              udp_data_processor};
  co_await proxy.Run();
}

}  // namespace socks5::server