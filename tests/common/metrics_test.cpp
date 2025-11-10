#include <gtest/gtest.h>
#include <socks5/common/metrics.hpp>
#include <thread>
#include <vector>

namespace socks5::common {

TEST(MetricsTest, BasicOperationsEnabled) {
  Metrics metrics;

  metrics.AddRecvBytes(100);
  metrics.AddSentBytes(200);
  EXPECT_EQ(metrics.GetRecvBytesTotal(), 100);
  EXPECT_EQ(metrics.GetSentBytesTotal(), 200);

  metrics.AddRecvBytes(50);
  EXPECT_EQ(metrics.GetRecvBytesTotal(), 150);

  metrics.Clear();
  EXPECT_EQ(metrics.GetRecvBytesTotal(), 0);
  EXPECT_EQ(metrics.GetSentBytesTotal(), 0);
}

TEST(MetricsTest, ThreadSafety) {
  Metrics metrics;
  constexpr size_t kThreadCount{4};
  constexpr size_t kIncrements{100000};
  std::vector<std::thread> threads;

  for (size_t i = 0; i < kThreadCount; ++i) {
    threads.emplace_back([&metrics]() {
      for (size_t j = 0; j < kIncrements; ++j) {
        metrics.AddRecvBytes(1);
        metrics.AddSentBytes(1);
      }
    });
  }

  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(metrics.GetRecvBytesTotal(), kThreadCount * kIncrements);
  EXPECT_EQ(metrics.GetSentBytesTotal(), kThreadCount * kIncrements);

  metrics.Clear();
  EXPECT_EQ(metrics.GetRecvBytesTotal(), 0);
}

}  // namespace socks5::common