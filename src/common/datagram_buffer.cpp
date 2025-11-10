#include <socks5/common/datagram_buffer.hpp>
#include <common/defs.hpp>

namespace socks5::common {

struct DatagramBuffer::Impl {
  // Internal buffer for the entire datagram with header and body.
  char* buf{nullptr};
  size_t buf_size{};

  char* datagram_header{nullptr};
  size_t datagram_header_size{};

  // Pointer to the datagram body.
  char* datagram_body{nullptr};
  // The size of the datagram body without the size of the datagram header.
  size_t datagram_body_size{};

  Impl(char* data, size_t size) : buf{data}, buf_size{size} {}
};

DatagramBuffer::DatagramBuffer(const DatagramBuffer&) noexcept = default;

DatagramBuffer::DatagramBuffer(DatagramBuffer&&) noexcept = default;

DatagramBuffer& DatagramBuffer::operator=(DatagramBuffer&&) noexcept = default;

DatagramBuffer::~DatagramBuffer() = default;

DatagramBuffer::DatagramBuffer(char* data, size_t size) noexcept
    : impl_{data, size} {}

const char* DatagramBuffer::Data() const noexcept {
  return impl_->datagram_body;
}

char* DatagramBuffer::Data() noexcept { return impl_->datagram_body; }

size_t DatagramBuffer::DataSize() const noexcept {
  return impl_->datagram_body_size;
}

const char* DatagramBuffer::Header() const noexcept {
  return impl_->datagram_header;
}

char* DatagramBuffer::Header() noexcept { return impl_->datagram_header; }

size_t DatagramBuffer::HeaderSize() const noexcept {
  return impl_->datagram_header_size;
}

const char* DatagramBuffer::BufData() const noexcept { return impl_->buf; }

char* DatagramBuffer::BufData() noexcept { return impl_->buf; }

size_t DatagramBuffer::BufSize() const noexcept { return impl_->buf_size; }

void DatagramBuffer::SetHeader(size_t size) noexcept {
  impl_->datagram_header = impl_->buf;
  impl_->datagram_header_size = size;
}

void DatagramBuffer::SetBody(char* data, size_t size) noexcept {
  impl_->datagram_body = data;
  impl_->datagram_body_size = size;
}

DatagramBuffer MakeDatagramBuffer(char* data, size_t size) noexcept {
  return DatagramBuffer{data, size};
}

}  // namespace socks5::common