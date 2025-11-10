#include <socks5/common/metrics.hpp>

namespace socks5::common {

void Metrics::AddRecvBytes(size_t recv_bytes) noexcept {
#ifndef SOCKS5_DISABLE_METRICS
  recv_bytes_total += recv_bytes;
#endif
}

void Metrics::AddSentBytes(size_t sent_bytes) noexcept {
#ifndef SOCKS5_DISABLE_METRICS
  sent_bytes_total += sent_bytes;
#endif
}

size_t Metrics::GetRecvBytesTotal() const noexcept {
#ifndef SOCKS5_DISABLE_METRICS
  return recv_bytes_total;
#else
  return 0;
#endif
}

size_t Metrics::GetSentBytesTotal() const noexcept {
#ifndef SOCKS5_DISABLE_METRICS
  return sent_bytes_total;
#else
  return 0;
#endif
}

void Metrics::Clear() noexcept {
#ifndef SOCKS5_DISABLE_METRICS
  recv_bytes_total = 0;
  sent_bytes_total = 0;
#endif
}

}  // namespace socks5::common
