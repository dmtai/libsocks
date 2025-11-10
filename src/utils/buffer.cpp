#include <socks5/utils/buffer.hpp>

namespace socks5::utils {

Buffer::Buffer(UnderlyingBuffer underlying_buf, size_t size) noexcept
    : buf_{std::move(underlying_buf)},
      buf_size_{size},
      reader_index_{},
      writer_index_{} {}

char* Buffer::Begin() noexcept { return buf_; }

const char* Buffer::Begin() const noexcept { return buf_; }

char* Buffer::BeginWrite() noexcept { return Begin() + writer_index_; }

const char* Buffer::BeginWrite() const noexcept {
  return Begin() + writer_index_;
}

const char* Buffer::BeginRead() const noexcept {
  return Begin() + reader_index_;
}

char* Buffer::BeginRead() noexcept { return Begin() + reader_index_; }

size_t Buffer::WritableBytes() const noexcept {
  return buf_size_ - writer_index_;
}

size_t Buffer::ReadableBytes() const noexcept {
  return writer_index_ - reader_index_;
}

size_t Buffer::Size() const noexcept { return buf_size_; }

void Buffer::Clear() noexcept {
  reader_index_ = 0;
  writer_index_ = 0;
}

bool operator==(const Buffer& lhs, const Buffer& rhs) noexcept {
  return lhs.ReadableBytes() == rhs.ReadableBytes() &&
         std::memcmp(lhs.BeginRead(), rhs.BeginRead(), lhs.ReadableBytes()) ==
             0;
}

}  // namespace socks5::utils