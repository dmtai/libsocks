#pragma once

#include <socks5/common/asio.hpp>
#include <utils/logger.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/server/handler_defs.hpp>
#include <server/relay_data_processors.hpp>
#include <type_traits>

namespace socks5::server {

namespace detail {

template <typename T>
using HandlerRef = std::add_lvalue_reference_t<std::decay_t<T>>;

template <typename Handler, typename = void>
struct IsCoroTcpRelayHandler : std::false_type {};

template <typename Handler>
struct IsCoroTcpRelayHandler<
    Handler, std::void_t<std::invoke_result_t<
                 HandlerRef<Handler>, asio::io_context&, socks5::tcp::socket,
                 socks5::tcp::socket, const Config&, common::Metrics&>>>
    : std::bool_constant<std::is_same_v<
          std::decay_t<std::invoke_result_t<
              HandlerRef<Handler>, asio::io_context&, socks5::tcp::socket,
              socks5::tcp::socket, const Config&, common::Metrics&>>,
          VoidAwait>> {};

template <typename Handler>
constexpr bool IsCoroTcpRelayHandlerV = IsCoroTcpRelayHandler<Handler>::value;

template <typename Handler>
constexpr bool IsTcpRelayHandlerV =
    std::is_invocable_r_v<void, HandlerRef<Handler>, asio::io_context&,
                          socks5::tcp::socket, socks5::tcp::socket,
                          const Config&, common::Metrics&>;

template <typename...>
struct InvalidTcpHandler : std::false_type {};

}  // namespace detail

using DefaultTcpRelayHandlerCb = VoidAwait (*)(net::TcpConnection,
                                               net::TcpConnection,
                                               const Config&);
using TcpRelayHandlerWithDataProcessorCb =
    VoidAwait (*)(net::TcpConnection, net::TcpConnection, const Config&,
                  const TcpRelayDataProcessor&);

template <typename Handler>
class TcpRelay final : utils::NonCopyable {
 public:
  using RelayHandler = Handler;

  TcpRelay(asio::io_context& io_context, net::TcpConnection client,
           net::TcpConnection server, const RelayHandler& handler,
           const Config& config, common::Metrics& metrics,
           const TcpRelayDataProcessor& tcp_data_processor) noexcept
      : io_context_{io_context},
        client_{std::move(client)},
        server_{std::move(server)},
        handler_{handler},
        config_{config},
        metrics_{metrics},
        tcp_relay_data_processor_{tcp_data_processor} {}

  VoidAwait Run() noexcept { co_await Relay(); }

 private:
  VoidAwait Relay() noexcept {
    try {
      if constexpr (std::is_same_v<std::decay_t<Handler>,
                                   DefaultTcpRelayHandlerCb>) {
        co_await handler_(std::move(client_), std::move(server_), config_);
      } else if constexpr (std::is_same_v<std::decay_t<Handler>,
                                          TcpRelayHandlerWithDataProcessorCb>) {
        co_await handler_(std::move(client_), std::move(server_), config_,
                          tcp_relay_data_processor_);
      } else if constexpr (detail::IsCoroTcpRelayHandlerV<Handler>) {
        co_await handler_(io_context_, std::move(client_.GetSocket()),
                          std::move(server_.GetSocket()), config_, metrics_);
      } else if constexpr (detail::IsTcpRelayHandlerV<Handler>) {
        handler_(io_context_, std::move(client_.GetSocket()),
                 std::move(server_.GetSocket()), config_, metrics_);
      } else {
        static_assert(detail::InvalidTcpHandler<Handler>::value,
                      "Invalid tcp relay handler type");
      }
    } catch (const std::exception& ex) {
      SOCKS5_LOG(error, "Tcp relay exception. Client: {}. Server: {}. {}",
                 net::ToString(client_), net::ToString(server_), ex.what());
    }
    co_return;
  }

  asio::io_context& io_context_;
  net::TcpConnection client_;
  net::TcpConnection server_;
  const RelayHandler& handler_;
  const Config& config_;
  common::Metrics& metrics_;
  const TcpRelayDataProcessor& tcp_relay_data_processor_;
};

VoidAwait DefaultTcpRelayHandler(net::TcpConnection from, net::TcpConnection to,
                                 const Config& config);
VoidAwait TcpRelayHandlerWithDataProcessor(
    net::TcpConnection from, net::TcpConnection to, const Config& config,
    const TcpRelayDataProcessor& data_processor);

}  // namespace socks5::server