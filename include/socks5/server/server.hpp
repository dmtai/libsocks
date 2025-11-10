#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/server/config.hpp>
#include <socks5/auth/server/user_auth_fwd.hpp>
#include <socks5/common/metrics.hpp>
#include <socks5/utils/fast_pimpl.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/common/api_macro.hpp>

namespace socks5::server {

namespace detail {

using ListenerRunner = std::function<void()>;

}  // namespace detail

/**
 * @brief Socks5 proxy server.
 */
class SOCKS5_API Server final : utils::NonCopyable {
 public:
  /**
   * @brief Constructs a server. Client code shouldn't call this constructor
   * directly. Client code must use ServerBuilder to construct the server. This
   * constructor is for internal use.
   */
  Server(IoContextPtr io_context, std::any tcp_relay_handler,
         std::any udp_relay_handler, detail::ListenerRunner listener_runner,
         ConfigPtr config_ptr, common::MetricsPtr metrics,
         auth::server::UserAuthCbPtr user_auth_cb,
         TcpRelayDataProcessorPtr tcp_data_processor,
         UdpRelayDataProcessorPtr udp_data_processor);

  /**
   * @brief Calls Wait() and destroys the server.
   */
  ~Server();

  /**
   * @brief Run the socks5 proxy server. Does not block execution.
   * Repeated calls will wait until the proxy server stops. The behavior is
   * similar to boost::asio io_context.run(). Thread-safe.
   *
   * @throws std::exception
   */
  void Run();

  /**
   * @brief Blocks execution until the socks5 proxy server is stopped.
   * Thread-safe.
   *
   * @throws std::exception
   */
  void Wait();

  /**
   * @brief Get the total number of bytes received by the socks5 proxy server.
   * Thread-safe.
   */
  size_t GetRecvBytesTotal() const noexcept;

  /**
   * @brief Get the total number of bytes sent by the socks5 proxy server.
   * Thread-safe.
   */
  size_t GetSentBytesTotal() const noexcept;

  /**
   * @brief Requests to stop the socks5 proxy server. This function does not
   * block, but instead simply signals proxy server to stop. The behavior is
   * similar to boost::asio io_context.stop(). Thread-safe.
   */
  void Stop() noexcept;

  /**
   * @brief Determine whether the proxy has been stopped. Thread-safe.
   */
  bool Stopped() noexcept;

  /**
   * @brief Get the internal boost::asio::io_contex object in which the server
   * is running.
   */
  asio::io_context& IOContext() noexcept;

  const asio::io_context& IOContext() const noexcept;

 private:
  void RunListener() const;
  void ResetComponents();

  struct Impl;
  constexpr static size_t kSize{408};
  constexpr static size_t kAlignment{8};
  utils::FastPimpl<Impl, kSize, kAlignment> impl_;
};

}  // namespace socks5::server