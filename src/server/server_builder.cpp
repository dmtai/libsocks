#include <server/listener.hpp>
#include <server/proxy.hpp>
#include <server/tcp_relay.hpp>
#include <socks5/common/asio.hpp>
#include <server/udp_relay.hpp>
#include <socks5/server/config.hpp>
#include <net/tcp_connection.hpp>
#include <net/udp_connection.hpp>
#include <socks5/common/metrics.hpp>
#include <server/handshake.hpp>
#include <socks5/server/handler_defs.hpp>
#include <socks5/server/server_builder.hpp>
#include <server/relay_data_processors.hpp>
#include <type_traits>
#include <utility>

namespace socks5::server {

namespace {

template <typename TcpRelayHandler, typename UdpRelayHandler>
using ServerProxy =
    Proxy<TcpRelay<TcpRelayHandler>, UdpRelay<UdpRelayHandler>, Handshake>;

template <typename TcpRelayHandler, typename UdpRelayHandler>
Server MakeServer(TcpRelayHandler tcp_relay_handler,
                  UdpRelayHandler udp_relay_handler, Config config,
                  auth::server::UserAuthCb user_auth_cb,
                  TcpRelayDataProcessor tcp_data_processor =
                      MakeDefaultTcpRelayDataProcessor(),
                  UdpRelayDataProcessor udp_data_processor =
                      MakeDefaultUdpRelayDataProcessor()) {
  const auto io_context_ptr = std::make_shared<asio::io_context>();
  const auto config_ptr = std::make_shared<Config>(std::move(config));
  const auto metrics_ptr = std::make_shared<common::Metrics>();
  const auto tcp_relay_handler_ptr =
      std::make_shared<TcpRelayHandler>(std::move(tcp_relay_handler));
  const auto udp_relay_handler_ptr =
      std::make_shared<UdpRelayHandler>(std::move(udp_relay_handler));
  const auto user_auth_cb_ptr =
      std::make_shared<auth::server::UserAuthCb>(std::move(user_auth_cb));
  const auto tcp_data_processor_ptr =
      std::make_shared<TcpRelayDataProcessor>(std::move(tcp_data_processor));
  const auto udp_data_processor_ptr =
      std::make_shared<UdpRelayDataProcessor>(std::move(udp_data_processor));
  const auto listener =
      std::make_shared<Listener<ServerProxy<TcpRelayHandler, UdpRelayHandler>>>(
          *io_context_ptr,
          tcp::endpoint{asio::ip::make_address(config_ptr->listener_addr.first),
                        config_ptr->listener_addr.second},
          *tcp_relay_handler_ptr, *udp_relay_handler_ptr, *config_ptr,
          *metrics_ptr, *user_auth_cb_ptr, *tcp_data_processor_ptr,
          *udp_data_processor_ptr);

  return Server{std::move(io_context_ptr),
                std::move(tcp_relay_handler_ptr),
                std::move(udp_relay_handler_ptr),
                [listener]() { listener->Run(); },
                std::move(config_ptr),
                std::move(metrics_ptr),
                std::move(user_auth_cb_ptr),
                std::move(tcp_data_processor_ptr),
                std::move(udp_data_processor_ptr)};
}

}  // namespace

struct ServerBuilder::Impl {
  Config config;
  auth::server::UserAuthCb user_auth_cb;
};

ServerBuilder::ServerBuilder(std::string addr, unsigned short port,
                             size_t threads_num)
    : impl_{Config{}, auth::server::DefaultUserAuthCb} {
  impl_->config.listener_addr = std::make_pair(std::move(addr), port);
  impl_->config.threads_num = threads_num;
}

ServerBuilder::ServerBuilder(ServerBuilder&&) noexcept = default;

ServerBuilder& ServerBuilder::operator=(ServerBuilder&&) noexcept = default;

ServerBuilder::~ServerBuilder() = default;

ServerBuilder& ServerBuilder::SetListener(std::string addr,
                                          unsigned short port) noexcept {
  impl_->config.listener_addr = std::make_pair(std::move(addr), port);
  return *this;
}

ServerBuilder& ServerBuilder::SetThreadsNum(size_t threads_num) noexcept {
  impl_->config.threads_num = threads_num;
  return *this;
}

ServerBuilder& ServerBuilder::SetHandshakeTimeout(size_t timeout) noexcept {
  impl_->config.handshake_timeout = timeout;
  return *this;
}

ServerBuilder& ServerBuilder::SetTcpRelayTimeout(size_t timeout) noexcept {
  impl_->config.tcp_relay_timeout = timeout;
  return *this;
}

ServerBuilder& ServerBuilder::SetUdpRelayTimeout(size_t timeout) noexcept {
  impl_->config.udp_relay_timeout = timeout;
  return *this;
}

ServerBuilder& ServerBuilder::SetUserAuthCb(
    auth::server::UserAuthCb user_auth_cb) {
  impl_->user_auth_cb = std::move(user_auth_cb);
  return *this;
}

ServerBuilder& ServerBuilder::SetAuthUsername(
    std::string auth_username) noexcept {
  impl_->config.auth_username = std::move(auth_username);
  return *this;
}

ServerBuilder& ServerBuilder::SetAuthPassword(
    std::string auth_password) noexcept {
  impl_->config.auth_password = std::move(auth_password);
  return *this;
}

ServerBuilder& ServerBuilder::EnableUserAuth(bool enable_user_auth) noexcept {
  impl_->config.enable_user_auth = enable_user_auth;
  return *this;
}

ServerBuilder& ServerBuilder::EnableTcpNodelay(
    bool enable_tcp_nodelay) noexcept {
  impl_->config.tcp_nodelay = enable_tcp_nodelay;
  return *this;
}

ServerBuilder& ServerBuilder::NeedToValidateAcceptedConnectionInBindCmd(
    bool need_to_validate) noexcept {
  impl_->config.bind_validate_accepted_conn = need_to_validate;
  return *this;
}

Server ServerBuilder::Dispatch(auto&& lhs, auto&& rhs) {
  using LhsType = std::decay_t<decltype(lhs)>;
  using RhsType = std::decay_t<decltype(rhs)>;
  if constexpr (std::is_same_v<LhsType,
                               detail::TcpHandlerWrapper::DataProcessor> &&
                std::is_same_v<RhsType,
                               detail::UdpHandlerWrapper::DataProcessor>) {
    return MakeServer(TcpRelayHandlerWithDataProcessor,
                      UdpRelayHandlerWithDataProcessor, impl_->config,
                      impl_->user_auth_cb, std::forward<decltype(lhs)>(lhs),
                      std::forward<decltype(rhs)>(rhs));
  } else if constexpr (std::is_same_v<
                           LhsType, detail::TcpHandlerWrapper::DataProcessor> &&
                       std::is_same_v<RhsType,
                                      detail::UdpHandlerWrapper::DefaultTag>) {
    return MakeServer(TcpRelayHandlerWithDataProcessor, DefaultUdpRelayHandler,
                      impl_->config, impl_->user_auth_cb,
                      std::forward<decltype(lhs)>(lhs));
  } else if constexpr (std::is_same_v<
                           LhsType, detail::TcpHandlerWrapper::DataProcessor>) {
    return MakeServer(TcpRelayHandlerWithDataProcessor,
                      std::forward<decltype(rhs)>(rhs), impl_->config,
                      impl_->user_auth_cb, std::forward<decltype(lhs)>(lhs));
  } else if constexpr (std::is_same_v<
                           RhsType, detail::UdpHandlerWrapper::DataProcessor> &&
                       std::is_same_v<LhsType,
                                      detail::TcpHandlerWrapper::DefaultTag>) {
    return MakeServer(DefaultTcpRelayHandler, UdpRelayHandlerWithDataProcessor,
                      impl_->config, impl_->user_auth_cb,
                      MakeDefaultTcpRelayDataProcessor(),
                      std::forward<decltype(rhs)>(rhs));
  } else if constexpr (std::is_same_v<
                           RhsType, detail::UdpHandlerWrapper::DataProcessor>) {
    return MakeServer(std::forward<decltype(lhs)>(lhs),
                      UdpRelayHandlerWithDataProcessor, impl_->config,
                      impl_->user_auth_cb, MakeDefaultTcpRelayDataProcessor(),
                      std::forward<decltype(rhs)>(rhs));
  } else if constexpr (std::is_same_v<LhsType,
                                      detail::TcpHandlerWrapper::DefaultTag> &&
                       std::is_same_v<RhsType,
                                      detail::UdpHandlerWrapper::DefaultTag>) {
    return MakeServer(DefaultTcpRelayHandler, DefaultUdpRelayHandler,
                      impl_->config, impl_->user_auth_cb);
  } else if constexpr (std::is_same_v<LhsType,
                                      detail::TcpHandlerWrapper::DefaultTag>) {
    return MakeServer(DefaultTcpRelayHandler, std::forward<decltype(rhs)>(rhs),
                      impl_->config, impl_->user_auth_cb);
  } else if constexpr (std::is_same_v<RhsType,
                                      detail::UdpHandlerWrapper::DefaultTag>) {
    return MakeServer(std::forward<decltype(lhs)>(lhs), DefaultUdpRelayHandler,
                      impl_->config, impl_->user_auth_cb);
  } else {
    return MakeServer(std::forward<decltype(lhs)>(lhs),
                      std::forward<decltype(rhs)>(rhs), impl_->config,
                      impl_->user_auth_cb);
  }
};

Server ServerBuilder::Build() {
  return MakeServer(DefaultTcpRelayHandler, DefaultUdpRelayHandler,
                    impl_->config, impl_->user_auth_cb);
}

Server ServerBuilder::Build(detail::TcpHandlerWrapper lhs_wrapper,
                            detail::UdpHandlerWrapper rhs_wrapper) {
  return std::visit(
      [&](auto&& lhs) -> Server {
        return std::visit(
            [&](auto&& rhs) -> Server {
              return Dispatch(std::forward<decltype(lhs)>(lhs),
                              std::forward<decltype(rhs)>(rhs));
            },
            std::move(rhs_wrapper.value));
      },
      std::move(lhs_wrapper.value));
}

ServerBuilder MakeServerBuilder(std::string addr, unsigned short port) {
  ServerBuilder server_builder{std::move(addr), port,
                               std::thread::hardware_concurrency()};
  return server_builder;
}

}  // namespace socks5::server
