#pragma once

#include <concepts>
#include <type_traits>

namespace socks5::utils {

template <typename T>
concept TriviallyCopyable = std::is_trivially_copyable_v<T>;

template <typename...>
struct AlwaysFalse : std::false_type {};

}  // namespace socks5::utils