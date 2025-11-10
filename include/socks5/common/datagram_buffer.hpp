#pragma once

#include <socks5/utils/fast_pimpl.hpp>
#include <socks5/utils/buffer.hpp>
#include <socks5/common/api_macro.hpp>
#include <stddef.h>

namespace socks5::common {

/**
 * @brief Buffer for receiving and parsing datagrams from socks5 proxy. Each
 * receive of a datagram into this buffer overwrites the data in it. The size
 * must be set large enough to accommodate the datagram's socks5 header and the
 * data itself.
 */
class SOCKS5_API DatagramBuffer final {
 public:
  /**
   * @brief Construct a new DatagramBuffer object.
   *
   * @param data data that the buffer will use.
   * @param size data size.
   */
  DatagramBuffer(char* data, size_t size) noexcept;

  DatagramBuffer(const DatagramBuffer&) noexcept;
  DatagramBuffer(DatagramBuffer&&) noexcept;
  DatagramBuffer& operator=(DatagramBuffer&&) noexcept;
  ~DatagramBuffer();

  /**
   * @brief Returns a pointer to the beginning of the buffer data.
   */
  const char* BufData() const noexcept;

  /**
   * @brief Returns a pointer to the beginning of the buffer data.
   */
  char* BufData() noexcept;

  /**
   * @brief Returns a buffer data size.
   */
  size_t BufSize() const noexcept;

  /**
   * @brief Returns a pointer to the beginning of the header of the last
   * datagram read into the buffer.
   */
  const char* Header() const noexcept;

  /**
   * @brief Returns a pointer to the beginning of the header of the last
   * datagram read into the buffer.
   */
  char* Header() noexcept;

  /**
   * @brief Returns a datagram header size of the last datagram read into the
   * buffer.
   */
  size_t HeaderSize() const noexcept;

  /**
   * @brief Returns a pointer to the datagram body of the last datagram read
   * into the buffer.
   */
  const char* Data() const noexcept;

  /**
   * @brief Returns a pointer to the datagram body of the last datagram read
   * into the buffer.
   */
  char* Data() noexcept;

  /**
   * @brief Returns a datagram body size of the last datagram read into the
   * buffer.
   */
  size_t DataSize() const noexcept;

  void SetHeader(size_t size) noexcept;
  void SetBody(char* data, size_t size) noexcept;

 private:
  struct Impl;
  constexpr static size_t kSize{48};
  constexpr static size_t kAlignment{8};
  utils::FastPimpl<Impl, kSize, kAlignment> impl_;
};

[[nodiscard]] SOCKS5_API DatagramBuffer
MakeDatagramBuffer(char* data, size_t size) noexcept;
template <size_t Size>
[[nodiscard]] SOCKS5_API DatagramBuffer
MakeDatagramBuffer(std::array<char, Size>& arr) noexcept {
  return MakeDatagramBuffer(arr.data(), arr.size());
}

}  // namespace socks5::common