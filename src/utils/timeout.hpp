#pragma once

#include <socks5/common/asio.hpp>

namespace socks5::utils {

VoidAwait Timeout(std::chrono::steady_clock::duration duration) noexcept;
VoidAwait Timeout(size_t duration) noexcept;

}  // namespace socks5::utils