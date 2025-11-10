#pragma once

#include <socks5/common/asio.hpp>
#include <utils/logger.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <server/proxy.hpp>
#include <socks5/server/config.hpp>
#include <socks5/common/metrics.hpp>
#include <net/utils.hpp>
#include <server/relay_data_processors.hpp>

namespace socks5::server {

template <typename Proxy>
class Listener final : public std::enable_shared_from_this<Listener<Proxy>>,
                       utils::NonCopyable {
 public:
  Listener(asio::io_context& io_context, tcp::endpoint endpoint,
           const typename Proxy::TcpRelayHandler& tcp_relay_handler,
           const typename Proxy::UdpRelayHandler& udp_relay_handler,
           const Config& config, common::Metrics& metrics,
           const auth::server::UserAuthCb& user_auth_cb,
           const TcpRelayDataProcessor& tcp_data_processor,
           const UdpRelayDataProcessor& udp_data_processor) noexcept
      : io_context_{io_context},
        acceptor_{io_context},
        tcp_relay_handler_{tcp_relay_handler},
        udp_relay_handler_{udp_relay_handler},
        endpoint_{std::move(endpoint)},
        config_{config},
        metrics_{metrics},
        user_auth_cb_{user_auth_cb},
        tcp_relay_data_processor_{tcp_data_processor},
        udp_relay_data_processor_{udp_data_processor} {
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint_);
    acceptor_.listen(asio::socket_base::max_listen_connections);
  }

  void Run() {
    SOCKS5_LOG(info, "Socks5 listener started on {}",
               net::ToString<tcp>(endpoint_));
    asio::co_spawn(
        io_context_,
        [self = this->shared_from_this()] { return self->Listen(); },
        asio::detached);
  }

 private:
  VoidAwait Listen() noexcept {
    for (;;) {
      try {
        auto [err, socket] =
            co_await acceptor_.async_accept(use_nothrow_awaitable);
        if (err) {
          SOCKS5_LOG(debug, "Error accepting new connection. msg={}",
                     err.message());
          continue;
        }
        SOCKS5_LOG(debug, "New connection accepted: {}",
                   net::ToString<tcp>(socket));
        if (config_.tcp_nodelay) {
          socket.set_option(tcp::no_delay{true});
        }
        AsyncRunProxy(std::move(socket));
      } catch (const std::exception& ex) {
        SOCKS5_LOG(error, ex.what());
      }
    }
  }

  void AsyncRunProxy(tcp::socket socket) {
    asio::co_spawn(
        asio::make_strand(io_context_),
        RunProxy<Proxy>(io_context_, std::move(socket), tcp_relay_handler_,
                        udp_relay_handler_, config_, metrics_, user_auth_cb_,
                        tcp_relay_data_processor_, udp_relay_data_processor_),
        asio::detached);
  }

  asio::io_context& io_context_;
  tcp::acceptor acceptor_;
  const typename Proxy::TcpRelayHandler& tcp_relay_handler_;
  const typename Proxy::UdpRelayHandler& udp_relay_handler_;
  tcp::endpoint endpoint_;
  const Config& config_;
  common::Metrics& metrics_;
  const auth::server::UserAuthCb& user_auth_cb_;
  const TcpRelayDataProcessor& tcp_relay_data_processor_;
  const UdpRelayDataProcessor& udp_relay_data_processor_;
};

}  // namespace socks5::server