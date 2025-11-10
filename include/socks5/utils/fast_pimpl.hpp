#pragma once

#include <cstddef>
#include <new>
#include <type_traits>
#include <utility>
#include <socks5/common/api_macro.hpp>

namespace socks5::utils {

template <class T, std::size_t Size, std::size_t Alignment, bool Strict = false>
class SOCKS5_API FastPimpl final {
 public:
  FastPimpl(FastPimpl&& v) noexcept(noexcept(T(std::declval<T>())))
      : FastPimpl(std::move(*v)) {}

  FastPimpl(const FastPimpl& v) noexcept(noexcept(T(std::declval<const T&>())))
      : FastPimpl(*v) {}

  FastPimpl& operator=(const FastPimpl& rhs) noexcept(
      noexcept(std::declval<T&>() = std::declval<const T&>())) {
    *AsHeld() = *rhs;
    return *this;
  }

  FastPimpl& operator=(FastPimpl&& rhs) noexcept(
      noexcept(std::declval<T&>() = std::declval<T>())) {
    *AsHeld() = std::move(*rhs);
    return *this;
  }

  template <typename... Args>
  explicit FastPimpl(Args&&... args) noexcept(
      noexcept(T(std::declval<Args>()...))) {
    ::new (AsHeld()) T(std::forward<Args>(args)...);
  }

  T* operator->() noexcept { return AsHeld(); }

  const T* operator->() const noexcept { return AsHeld(); }

  T& operator*() noexcept { return *AsHeld(); }

  const T& operator*() const noexcept { return *AsHeld(); }

  ~FastPimpl() noexcept {
    Validate<sizeof(T), alignof(T)>();
    AsHeld()->~T();
  }

 private:
  template <std::size_t ActualSize, std::size_t ActualAlignment>
  static void Validate() noexcept {
    static_assert(Size >= ActualSize, "Invalid Size: Size >= sizeof(T) failed");
    static_assert(!Strict || Size == ActualSize,
                  "Invalid Size: Size == sizeof(T) failed");

    static_assert(Alignment % ActualAlignment == 0,
                  "Invalid Alignment: Alignment % alignof(T) == 0 failed");
    static_assert(!Strict || Alignment == ActualAlignment,
                  "Invalid Alignment: Alignment == alignof(T) failed");
  }

  alignas(Alignment) std::byte storage_[Size];

  T* AsHeld() noexcept { return reinterpret_cast<T*>(&storage_); }

  const T* AsHeld() const noexcept {
    return reinterpret_cast<const T*>(&storage_);
  }
};

}  // namespace socks5::utils