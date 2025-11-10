#include <socks5/utils/watchdog.hpp>
#include <utils/logger.hpp>

namespace socks5::utils {

namespace {

constexpr double kTimerTmoDivider{3};

}  // namespace

struct Watchdog::Impl {
  asio::steady_timer timer;
  int64_t interval;
  std::chrono::seconds timeout;
  asio::cancellation_signal cancel;
  std::atomic_int64_t last_update_time{};

  Impl(const asio::any_io_executor& executor, int64_t i, int64_t t) noexcept
      : timer{executor}, interval{i}, timeout{t} {}
};

Watchdog::Watchdog(const asio::any_io_executor& executor,
                   size_t interval) noexcept
    : impl_{executor, static_cast<int64_t>(interval),
            static_cast<int64_t>(std::ceil(interval / kTimerTmoDivider))} {}

Watchdog::Watchdog(const asio::any_io_executor& executor, size_t interval,
                   int64_t timeout) noexcept
    : impl_{executor, static_cast<int64_t>(interval), timeout} {}

Watchdog::~Watchdog() = default;

void Watchdog::Update() noexcept {
  impl_->last_update_time = static_cast<int64_t>(std::time(nullptr));
}

VoidAwait Watchdog::Run() noexcept {
  try {
    for (;;) {
      impl_->timer.expires_after(impl_->timeout);
      const auto [err] =
          co_await impl_->timer.async_wait(use_nothrow_awaitable);
      if (err || impl_->last_update_time == -1) {
        impl_->cancel.emit(asio::cancellation_type::terminal);
        co_return;
      }
      if (impl_->last_update_time == 0) {
        continue;
      }
      const auto now = static_cast<int64_t>(std::time(nullptr));
      if (now == -1) {
        impl_->cancel.emit(asio::cancellation_type::terminal);
        co_return;
      }
      const auto diff = now - impl_->last_update_time;
      if (diff >= impl_->interval) {
        impl_->cancel.emit(asio::cancellation_type::terminal);
        co_return;
      }
    }
  } catch (const std::exception& ex) {
    SOCKS5_LOG(error, "Watchdog exception: {}", ex.what());
    impl_->cancel.emit(asio::cancellation_type::terminal);
  }
}

CancellationSlot Watchdog::Slot() noexcept { return impl_->cancel.slot(); }

void Watchdog::Stop() noexcept { impl_->timer.cancel(); }

void Watchdog::Reset() noexcept { impl_->last_update_time = 0; }

}  // namespace socks5::utils