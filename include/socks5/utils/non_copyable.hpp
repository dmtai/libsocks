#pragma once

#include <socks5/common/api_macro.hpp>

namespace socks5::utils {

class SOCKS5_API NonCopyable {
 protected:
  NonCopyable() = default;
  NonCopyable(const NonCopyable&) = delete;
  NonCopyable& operator=(const NonCopyable&) = delete;
  NonCopyable(NonCopyable&&) noexcept = default;
  NonCopyable& operator=(NonCopyable&&) noexcept = default;
};

}  // namespace socks5::utils