#pragma once

#include <socks5/common/address.hpp>
#include <socks5/server/server.hpp>
#include <socks5/utils/fast_pimpl.hpp>
#include <socks5/auth/server/user_auth_fwd.hpp>
#include <socks5/common/api_macro.hpp>
#include <socks5/utils/type_traits.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <functional>
#include <utility>
#include <variant>

namespace socks5::server {

namespace detail {

struct TcpHandlerWrapper final {
  using DefaultTag = std::monostate;
  using Handler =
      std::function<void(socks5::asio::io_context&, socks5::tcp::socket,
                         socks5::tcp::socket, const Config&, common::Metrics&)>;
  using AwaitableHandler = std::function<socks5::VoidAwait(
      socks5::asio::io_context&, socks5::tcp::socket, socks5::tcp::socket,
      const Config&, common::Metrics&)>;
  using DataProcessor = TcpRelayDataProcessor;
  using Variant =
      std::variant<DefaultTag, Handler, AwaitableHandler, DataProcessor>;

  TcpHandlerWrapper() : value(DefaultTag{}) {}
  explicit TcpHandlerWrapper(DefaultTag tag) : value(tag) {}
  explicit TcpHandlerWrapper(Handler handler) : value(std::move(handler)) {}
  explicit TcpHandlerWrapper(AwaitableHandler handler)
      : value(std::move(handler)) {}
  explicit TcpHandlerWrapper(DataProcessor processor)
      : value(std::move(processor)) {}

  Variant value;
};

struct UdpHandlerWrapper final {
  using DefaultTag = std::monostate;
  using Handler =
      std::function<void(socks5::asio::io_context&, tcp::socket, udp::socket,
                         common::Address, const Config&, common::Metrics&)>;
  using AwaitableHandler = std::function<socks5::VoidAwait(
      socks5::asio::io_context&, tcp::socket, udp::socket, common::Address,
      const Config&, common::Metrics&)>;
  using DataProcessor = UdpRelayDataProcessor;
  using Variant =
      std::variant<DefaultTag, Handler, AwaitableHandler, DataProcessor>;

  UdpHandlerWrapper() : value(DefaultTag{}) {}
  explicit UdpHandlerWrapper(DefaultTag tag) : value(tag) {}
  explicit UdpHandlerWrapper(Handler handler) : value(std::move(handler)) {}
  explicit UdpHandlerWrapper(AwaitableHandler handler)
      : value(std::move(handler)) {}
  explicit UdpHandlerWrapper(DataProcessor processor)
      : value(std::move(processor)) {}

  Variant value;
};

template <typename Handler>
TcpHandlerWrapper WrapTcpHandler(Handler&& handler) {
  using Decayed = std::decay_t<Handler>;
  if constexpr (std::is_same_v<Decayed, TcpHandlerWrapper>) {
    return std::forward<Handler>(handler);
  } else if constexpr (std::is_same_v<Decayed, std::nullptr_t>) {
    return TcpHandlerWrapper{};
  } else if constexpr (std::is_same_v<Decayed, TcpRelayDataProcessor>) {
    return TcpHandlerWrapper{
        TcpHandlerWrapper::DataProcessor(std::forward<Handler>(handler))};
  } else if constexpr (std::is_constructible_v<
                           typename TcpHandlerWrapper::AwaitableHandler,
                           Handler>) {
    return TcpHandlerWrapper{typename TcpHandlerWrapper::AwaitableHandler(
        std::forward<Handler>(handler))};
  } else if constexpr (std::is_constructible_v<
                           typename TcpHandlerWrapper::Handler, Handler>) {
    return TcpHandlerWrapper{
        typename TcpHandlerWrapper::Handler(std::forward<Handler>(handler))};
  } else {
    static_assert(utils::AlwaysFalse<Handler>::value,
                  "Unsupported tcp handler type");
  }
}

template <typename Handler>
UdpHandlerWrapper WrapUdpHandler(Handler&& handler) {
  using Decayed = std::decay_t<Handler>;
  if constexpr (std::is_same_v<Decayed, UdpHandlerWrapper>) {
    return std::forward<Handler>(handler);
  } else if constexpr (std::is_same_v<Decayed, std::nullptr_t>) {
    return UdpHandlerWrapper{};
  } else if constexpr (std::is_same_v<Decayed, UdpRelayDataProcessor>) {
    return UdpHandlerWrapper{
        UdpHandlerWrapper::DataProcessor(std::forward<Handler>(handler))};
  } else if constexpr (std::is_constructible_v<
                           typename UdpHandlerWrapper::AwaitableHandler,
                           Handler>) {
    return UdpHandlerWrapper{typename UdpHandlerWrapper::AwaitableHandler(
        std::forward<Handler>(handler))};
  } else if constexpr (std::is_constructible_v<
                           typename UdpHandlerWrapper::Handler, Handler>) {
    return UdpHandlerWrapper{
        typename UdpHandlerWrapper::Handler(std::forward<Handler>(handler))};
  } else {
    static_assert(utils::AlwaysFalse<Handler>::value,
                  "Unsupported udp handler type");
  }
}

}  // namespace detail

/**
 * @brief Socks5 proxy server builder.
 */
class SOCKS5_API ServerBuilder final : utils::NonCopyable {
 public:
  /**
   * @brief Construct a new ServerBuilder object.
   *
   * @param addr socks5 proxy server IPv4/IPv6 address as a string. IP "0.0.0.0"
   * is not supported.
   * @param port socks5 proxy server port.
   * @param threads_num number of threads that will be created for the socks5
   * proxy server and on which it will run.
   * @throws std::exception
   */
  ServerBuilder(std::string addr, unsigned short port, size_t threads_num);

  ServerBuilder(ServerBuilder&&) noexcept;
  ServerBuilder& operator=(ServerBuilder&&) noexcept;
  ~ServerBuilder();

  /**
   * @brief Set socks5 proxy server address and port. IP "0.0.0.0" is not
   * supported.
   *
   * @param addr socks5 proxy server IPv4/IPv6 address as a string.
   * @param port socks5 proxy server port.
   * @return ServerBuilder&
   */
  ServerBuilder& SetListener(std::string addr, unsigned short port) noexcept;

  /**
   * @brief Set number of threads that will be created for the socks5 proxy
   * server and on which it will run.
   *
   * @param threads_num number of threads.
   * @return ServerBuilder&
   */
  ServerBuilder& SetThreadsNum(size_t threads_num) noexcept;

  /**
   * @brief Set a timeout in seconds for establishing socks5 connection(client
   * greeting, server choice, authentication, client request, server reply).
   *
   * @param timeout timeout in seconds.
   * @return ServerBuilder&
   */
  ServerBuilder& SetHandshakeTimeout(size_t timeout) noexcept;

  /**
   * @brief Set a timeout in seconds on socket io during tcp relay(CONNECT, BIND
   * commands).
   *
   * @param timeout timeout in seconds.
   * @return ServerBuilder&
   */
  ServerBuilder& SetTcpRelayTimeout(size_t timeout) noexcept;

  /**
   * @brief Set a timeout in seconds on socket io during udp relay(UDP ASSOCIATE
   * command).
   *
   * @param timeout timeout in seconds.
   * @return ServerBuilder&
   */
  ServerBuilder& SetUdpRelayTimeout(size_t timeout) noexcept;

  /**
   * @brief Set a callback that will be called for authentication when the
   * client will establishes a connection if authentication has been enabled.
   *
   * @param user_auth_cb callback for authentication.
   * @return ServerBuilder&
   * @throws std::exception
   */
  ServerBuilder& SetUserAuthCb(auth::server::UserAuthCb user_auth_cb);

  /**
   * @brief Set the authentication username that will be used in the default
   * authentication callback if authentication has been enabled.
   *
   * @param auth_username the username that the client must send to
   * authenticate when using the default auth callback.
   * @return ServerBuilder&
   */
  ServerBuilder& SetAuthUsername(std::string auth_username) noexcept;

  /**
   * @brief Set the authentication password that will be used in the default
   * authentication callback if authentication has been enabled.
   *
   * @param auth_password the password that the client must send to
   * authenticate when using the default auth callback.
   * @return ServerBuilder&
   */
  ServerBuilder& SetAuthPassword(std::string auth_password) noexcept;

  /**
   * @brief Enable authentication. Disabled by default.
   *
   * @param enable_user_auth enable or disable authentication.
   * @return ServerBuilder&
   */
  ServerBuilder& EnableUserAuth(bool enable_user_auth) noexcept;

  /**
   * @brief Enable TCP_NODELAY socket option(Nagle's algorithm) on all tcp
   * sockets on the socks5 proxy server. TCP_NODELAY disabled by default.
   *
   * @param enable_tcp_nodelay enable or disable TCP_NODELAY.
   * @return ServerBuilder&
   */
  ServerBuilder& EnableTcpNodelay(bool enable_tcp_nodelay) noexcept;

  /**
   * @brief Set whether to validate incoming connections when using BIND.
   * Disabled by default.
   *
   * @param need_to_validate enable or disable validation.
   * @return ServerBuilder&
   */
  ServerBuilder& NeedToValidateAcceptedConnectionInBindCmd(
      bool need_to_validate) noexcept;

  /**
   * @brief Build a Server with the specified parameters.
   *
   * @return Server
   * @throws std::exception
   */
  [[nodiscard]] Server Build();

  /**
   * @brief Build a Server with the specified parameters. Accepts callbacks of
   * tcp/udp handlers or data processors as arguments. Handlers accept sockets
   * and implement the logic of relaying tcp/udp traffic between clients and
   * servers. Data processors, if passed, process the data relayed by the socks5
   * proxy server.
   *
   * Tcp/udp handlers should be passed if you need to implement your own logic
   * for relaying tcp/udp traffic. Data processors should be passed if the
   * default logic for relaying tcp/udp traffic is suitable, but you need to
   * implement the logic for processing relayed data.
   *
   * A handler is a low-level entity that provides greater control but is more
   * complex to implement. A data processor is simpler to implement and allows
   * you to focus on processing and sending data.
   *
   * @tparam T
   * CoroTcpRelayHandlerCb/TcpRelayHandlerCb/TcpRelayDataProcessor/nullptr
   * (from include/server/handler_defs.hpp or
   * include/server/relay_data_processors_defs.hpp).
   * @tparam U
   * CoroUdpRelayHandlerCb/UdpRelayHandlerCb/UdpRelayDataProcessor/nullptr
   * (from include/server/handler_defs.hpp or
   * include/server/relay_data_processors_defs.hpp).
   * @param lhs handler callbacks corresponding to types
   * CoroTcpRelayHandlerCb/TcpRelayHandlerCb(from
   * include/server/handler_defs.hpp) or data processor callback corresponding
   * to type TcpRelayDataProcessor(from
   * include/server/relay_data_processors_defs.hpp) or nullptr if you need
   * default tcp processing logic.
   * @param rhs handler callbacks corresponding to types
   * CoroUdpRelayHandlerCb/UdpRelayHandlerCb(from
   * include/server/handler_defs.hpp) or data processor callback corresponding
   * to type UdpRelayDataProcessor(from
   * include/server/relay_data_processors_defs.hpp) or nullptr if you need
   * default udp processing logic.
   * @return Server
   * @throws std::exception
   */
  template <typename T, typename U>
  [[nodiscard]] Server Build(T lhs, U rhs) {
    return Build(detail::WrapTcpHandler(std::forward<T>(lhs)),
                 detail::WrapUdpHandler(std::forward<U>(rhs)));
  }

 private:
  [[nodiscard]] Server Build(detail::TcpHandlerWrapper lhs,
                             detail::UdpHandlerWrapper rhs);
  Server Dispatch(auto&& lhs, auto&& rhs);

  struct Impl;
  constexpr static size_t kSize{308};
  constexpr static size_t kAlignment{8};
  utils::FastPimpl<Impl, kSize, kAlignment> impl_;
};

/**
 * @brief Construct a new ServerBuilder object.
 *
 * @param addr socks5 proxy server IPv4/IPv6 address as a string. IP "0.0.0.0"
 * is not supported.
 * @param port socks5 proxy server port.
 * @throws std::exception
 */
SOCKS5_API ServerBuilder MakeServerBuilder(std::string addr,
                                           unsigned short port);

}  // namespace socks5::server