#pragma once

#include <array>
#include <stddef.h>
#include <cstring>
#include <cassert>
#include <socks5/utils/type_traits.hpp>

namespace socks5::utils {

class Buffer {
 public:
  using UnderlyingBuffer = char*;

  friend bool operator==(const Buffer& lhs, const Buffer& rhs) noexcept;

  Buffer(UnderlyingBuffer underlying_buf, size_t size) noexcept;

  char* Begin() noexcept;
  const char* Begin() const noexcept;
  char* BeginWrite() noexcept;
  const char* BeginWrite() const noexcept;
  const char* BeginRead() const noexcept;
  char* BeginRead() noexcept;
  size_t WritableBytes() const noexcept;
  size_t ReadableBytes() const noexcept;
  size_t Size() const noexcept;
  void Clear() noexcept;

  const auto& HasWritten(size_t len) noexcept {
    assert(WritableBytes() >= len);
    writer_index_ += len;
    return *this;
  }

  const auto& SeekToBegin() noexcept {
    reader_index_ = 0;
    return *this;
  }

  const auto& Seek(size_t len) noexcept {
    assert(ReadableBytes() >= len);
    if (len < ReadableBytes()) {
      reader_index_ += len;
    } else {
      SeekToBegin();
    }
    return *this;
  }

  template <typename T>
  void Peek(T* output_buf, size_t len) const noexcept {
    assert(ReadableBytes() >= len);
    std::memcpy(reinterpret_cast<void*>(output_buf), BeginRead(), len);
  }

  template <typename T>
  T Read() noexcept {
    T output_buf;
    Peek(&output_buf, sizeof(output_buf));
    Seek(sizeof(output_buf));
    return output_buf;
  }

  template <typename T>
  void Read(T& output_buf) noexcept {
    Peek(&output_buf, sizeof(output_buf));
    Seek(sizeof(output_buf));
  }

  template <typename T, size_t ArrSize>
  void Read(std::array<T, ArrSize>& output_buf, size_t len) noexcept {
    assert(ArrSize >= len);
    Peek(output_buf.data(), len);
    Seek(len);
  }

  template <typename T, size_t ArrSize>
  void Read(std::array<T, ArrSize>& output_buf) noexcept {
    Peek(output_buf.data(), ArrSize);
    Seek(ArrSize);
  }

  template <typename T>
  T ReadFromEnd() noexcept {
    const auto offset = static_cast<ptrdiff_t>(writer_index_ - sizeof(T));
    assert(offset >= 0);
    reader_index_ = offset;
    return Read<T>();
  }

  template <TriviallyCopyable T>
  void Append(const T* data, size_t len) noexcept {
    assert(WritableBytes() >= len);
    std::memcpy(BeginWrite(), reinterpret_cast<const void*>(data), len);
    HasWritten(len);
  }

  template <TriviallyCopyable T>
  void Append(const T& data) noexcept {
    Append(&data, sizeof(data));
  }

  template <typename T, size_t ArrSize>
  void Append(const std::array<T, ArrSize>& data,
              size_t len = ArrSize) noexcept {
    Append(data.data(), len);
  }

 protected:
  UnderlyingBuffer buf_;
  size_t buf_size_{};
  size_t reader_index_;
  size_t writer_index_;
};

template <typename T>
Buffer MakeBuffer(T& underlying_buf) noexcept {
  Buffer result_buf{underlying_buf.Begin(), underlying_buf.Size()};
  result_buf.HasWritten(underlying_buf.ReadableBytes());
  return result_buf;
}

bool operator==(const Buffer& lhs, const Buffer& rhs) noexcept;

template <size_t BufSize>
class StaticBuffer final : public Buffer {
 public:
  template <size_t LhsSize, size_t RhsSize>
  friend bool operator==(const StaticBuffer<LhsSize>& lhs,
                         const StaticBuffer<RhsSize>& rhs) noexcept;

  using UnderlyingBuffer = std::array<char, BufSize>;

  StaticBuffer() noexcept : Buffer{nullptr, BufSize} {
    buf_ = static_buf_.data();
  }

  StaticBuffer(const StaticBuffer& other) noexcept : Buffer{other} {
    static_buf_ = other.static_buf_;
    buf_ = static_buf_.data();
  }

  StaticBuffer& operator=(const StaticBuffer& other) noexcept {
    if (this == &other) {
      return *this;
    }
    Buffer::operator=(other);
    static_buf_ = other.static_buf_;
    buf_ = static_buf_.data();
    return *this;
  }

  StaticBuffer(StaticBuffer&& other) noexcept : Buffer{other} {
    static_buf_ = std::move(other.static_buf_);
    buf_ = static_buf_.data();
  }

  StaticBuffer& operator=(StaticBuffer&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    Buffer::operator=(std::move(other));
    static_buf_ = std::move(other.static_buf_);
    buf_ = static_buf_.data();
    return *this;
  }

 private:
  UnderlyingBuffer static_buf_;
};

template <size_t LhsSize, size_t RhsSize>
bool operator==(const StaticBuffer<LhsSize>& lhs,
                const StaticBuffer<RhsSize>& rhs) noexcept {
  return static_cast<Buffer>(lhs) == static_cast<Buffer>(rhs);
}

}  // namespace socks5::utils