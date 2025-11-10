#pragma once

#include <string>
#include <array>
#include <algorithm>

namespace socks5::utils {

template <std::size_t N>
std::array<unsigned char, N> ToArray(std::string_view sv) {
  if (sv.size() > N)
    throw std::runtime_error("string_view too large for array");

  std::array<unsigned char, N> arr{};
  std::copy_n(sv.begin(), std::min(sv.size(), N), arr.begin());
  return arr;
}

template <size_t N>
std::string_view ToSv(const std::array<uint8_t, N>& arr, size_t size) {
  return std::string_view{reinterpret_cast<const char*>(arr.data()), size};
}

}  // namespace socks5::utils