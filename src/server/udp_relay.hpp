#pragma once

#include <socks5/common/asio.hpp>
#include <utils/logger.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <proto/proto.hpp>
#include <common/addr_utils.hpp>
#include <net/utils.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <net/udp_connection.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/server/handler_defs.hpp>
#include <server/relay_data_processors.hpp>
#include <type_traits>

namespace socks5::server {

namespace detail {

template <typename T>
using HandlerRef = std::add_lvalue_reference_t<std::decay_t<T>>;

template <typename Handler, typename = void>
struct IsCoroUdpRelayHandler : std::false_type {};

template <typename Handler>
struct IsCoroUdpRelayHandler<
    Handler,
    std::void_t<std::invoke_result_t<HandlerRef<Handler>, asio::io_context&,
                                     tcp::socket, udp::socket, common::Address,
                                     const Config&, common::Metrics&>>>
    : std::bool_constant<std::is_same_v<
          std::decay_t<std::invoke_result_t<
              HandlerRef<Handler>, asio::io_context&, tcp::socket, udp::socket,
              common::Address, const Config&, common::Metrics&>>,
          VoidAwait>> {};

template <typename Handler>
constexpr bool IsCoroUdpRelayHandlerV = IsCoroUdpRelayHandler<Handler>::value;

template <typename Handler>
constexpr bool IsUdpRelayHandlerV =
    std::is_invocable_r_v<void, HandlerRef<Handler>, asio::io_context&,
                          tcp::socket, udp::socket, common::Address,
                          const Config&, common::Metrics&>;

template <typename...>
struct InvalidUdpHandler : std::false_type {};

}  // namespace detail

using DefaultUdpRelayHandlerCb = VoidAwait (*)(net::TcpConnection,
                                               net::UdpConnection, proto::Addr,
                                               const Config&, common::Metrics&);
using UdpRelayHandlerWithDataProcessorCb = VoidAwait (*)(
    net::TcpConnection, net::UdpConnection, proto::Addr, const Config&,
    common::Metrics&, const UdpRelayDataProcessor&);

template <typename Handler>
class UdpRelay final : utils::NonCopyable {
 public:
  using RelayHandler = Handler;

  UdpRelay(asio::io_context& io_context, net::TcpConnection client,
           net::UdpConnection proxy, proto::Addr client_addr,
           const RelayHandler& handler, const Config& config,
           common::Metrics& metrics,
           const UdpRelayDataProcessor& udp_data_processor) noexcept
      : io_context_{io_context},
        client_{std::move(client)},
        proxy_{std::move(proxy)},
        client_addr_{std::move(client_addr)},
        handler_{handler},
        config_{config},
        metrics_{metrics},
        udp_relay_data_processor_{udp_data_processor} {}

  VoidAwait Run() noexcept { co_await Relay(); }

 private:
  VoidAwait Relay() noexcept {
    try {
      if constexpr (std::is_same_v<std::decay_t<Handler>,
                                   DefaultUdpRelayHandlerCb>) {
        co_await handler_(std::move(client_), std::move(proxy_),
                          std::move(client_addr_), config_, metrics_);
      } else if constexpr (std::is_same_v<std::decay_t<Handler>,
                                          UdpRelayHandlerWithDataProcessorCb>) {
        co_await handler_(std::move(client_), std::move(proxy_),
                          std::move(client_addr_), config_, metrics_,
                          udp_relay_data_processor_);
      } else if constexpr (detail::IsCoroUdpRelayHandlerV<Handler>) {
        co_await handler_(io_context_, std::move(client_.GetSocket()),
                          std::move(proxy_.GetSocket()),
                          common::Address{std::move(client_addr_)}, config_,
                          metrics_);
      } else if constexpr (detail::IsUdpRelayHandlerV<Handler>) {
        handler_(io_context_, std::move(client_.GetSocket()),
                 std::move(proxy_.GetSocket()),
                 common::Address{std::move(client_addr_)}, config_, metrics_);
      } else {
        static_assert(detail::InvalidUdpHandler<Handler>::value,
                      "Invalid udp relay handler type");
      }
    } catch (const std::exception& ex) {
      SOCKS5_LOG(error, "Udp relay exception. {}", ex.what());
    }
    co_return;
  }

  asio::io_context& io_context_;
  net::TcpConnection client_;
  net::UdpConnection proxy_;
  const proto::Addr client_addr_;
  const RelayHandler& handler_;
  const Config& config_;
  common::Metrics& metrics_;
  const UdpRelayDataProcessor& udp_relay_data_processor_;
};

VoidAwait DefaultUdpRelayHandler(net::TcpConnection client,
                                 net::UdpConnection proxy,
                                 proto::Addr client_addr, const Config& config,
                                 common::Metrics& metrics);
VoidAwait UdpRelayHandlerWithDataProcessor(
    net::TcpConnection client, net::UdpConnection proxy,
    proto::Addr client_addr, const Config& config, common::Metrics& metrics,
    const UdpRelayDataProcessor& data_processor);

}  // namespace socks5::server