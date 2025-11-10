#pragma once

#include <boost/container/small_vector.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/common/asio.hpp>

namespace socks5::server {

class SentRelayData final {
 public:
  static constexpr size_t kRelayDataVecSize{128};
  using RelayDataVec =
      boost::container::small_vector<RelayData, kRelayDataVecSize>;

  void Send(const char* data, size_t size);
  void Clear() noexcept;

  template <typename T>
  BoolAwait ForEach(T&& cb) const
      noexcept(noexcept(cb(std::declval<const RelayData&>()))) {
    for (const auto& relay_data : data_) {
      if (!co_await cb(relay_data)) {
        co_return false;
      }
    }
    co_return true;
  }

 private:
  RelayDataVec data_;
};

}  // namespace socks5::server