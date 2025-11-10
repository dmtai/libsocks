#include <utils/timeout.hpp>
#include <utils/logger.hpp>

namespace socks5::utils {

VoidAwait Timeout(std::chrono::steady_clock::duration duration) noexcept {
  try {
    asio::steady_timer timer{co_await asio::this_coro::executor};
    timer.expires_after(duration);
    co_await timer.async_wait(use_nothrow_awaitable);
  } catch (const std::exception& ex) {
    SOCKS5_LOG(error, "Timer exception. {}", ex.what());
  }
}

VoidAwait Timeout(size_t duration) noexcept {
  co_await Timeout(std::chrono::milliseconds{duration});
}

}  // namespace socks5::utils