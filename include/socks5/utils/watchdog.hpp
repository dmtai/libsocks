#pragma once

#include <socks5/common/asio.hpp>
#include <socks5/common/api_macro.hpp>
#include <socks5/utils/fast_pimpl.hpp>
#include <chrono>
#include <atomic>

namespace socks5::utils {

/**
 * @brief Class for canceling coroutines. If it is not updated within the
 * interval, the Run method will be terminated and the cancellation slot will be
 * cancelled.
 */
class SOCKS5_API Watchdog final {
 public:
  /**
   * @brief Construct an object for canceling coroutines on a timer.
   *
   * @param executor the executor on which the object will be launched.
   * @param interval interval in seconds during which the Update() must be
   * called to avoid cancellation and completion of the Run().
   */
  Watchdog(const asio::any_io_executor& executor, size_t interval) noexcept;

  Watchdog(const asio::any_io_executor& executor, size_t interval,
           int64_t timeout) noexcept;

  ~Watchdog();

  /**
   * @brief Update the timer. If it is not updated within the interval passed in
   * the constructor, the constellation slot will be canceled and the Run method
   * will terminate. Thread-safe.
   */
  void Update() noexcept;

  /**
   * @brief Run the watchdog. However, the timer will only begin counting AFTER
   * the first call to Update. Until the first call to Update, Run will never
   * complete.
   *
   * @return asio::awaitable<void>
   */
  VoidAwait Run() noexcept;

  /**
   * @brief Return cancellation slot.
   *
   * @return boost::asio::cancellation_slot
   */
  CancellationSlot Slot() noexcept;

  void Stop() noexcept;
  void Reset() noexcept;

 private:
  struct Impl;
  constexpr static size_t kSize{152};
  constexpr static size_t kAlignment{8};
  utils::FastPimpl<Impl, kSize, kAlignment> impl_;
};

}  // namespace socks5::utils