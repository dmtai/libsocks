#include <server/sent_relay_data.hpp>

namespace socks5::server {

void SentRelayData::Send(const char* data, size_t size) {
  data_.push_back({data, size});
}

void SentRelayData::Clear() noexcept { data_.clear(); }

}  // namespace socks5::server