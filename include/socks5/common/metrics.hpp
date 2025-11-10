#pragma once

#include <atomic>
#include <memory>
#include <socks5/utils/non_copyable.hpp>
#include <socks5/common/api_macro.hpp>

namespace socks5::common {

/**
 * @brief Metrics socks5 proxy server.
 */
class SOCKS5_API Metrics final : utils::NonCopyable {
 public:
  /**
   * @brief Add the size of the data received by the socks5 proxy server.
   * Thread-safe.
   *
   * @param recv_bytes the size of the data received by the server since
   * startup.
   */
  void AddRecvBytes(size_t recv_bytes) noexcept;

  /**
   * @brief Add the size of the data sent by the socks5 proxy server.
   * Thread-safe.
   *
   * @param sent_bytes the size of the data sent by the server since startup.
   */
  void AddSentBytes(size_t sent_bytes) noexcept;

  /**
   * @brief Get the total number of bytes received by the socks5 proxy server
   * since startup. Thread-safe.
   */
  size_t GetRecvBytesTotal() const noexcept;

  /**
   * @brief Get the total number of bytes sent by the socks5 proxy server since
   * startup. Thread-safe.
   */
  size_t GetSentBytesTotal() const noexcept;

  /**
   * @brief Clear all metrics. Thread-safe.
   */
  void Clear() noexcept;

 private:
  std::atomic_size_t recv_bytes_total{};
  std::atomic_size_t sent_bytes_total{};
};

using MetricsPtr = std::shared_ptr<Metrics>;

}  // namespace socks5::common