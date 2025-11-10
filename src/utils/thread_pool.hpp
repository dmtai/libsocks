#pragma once

#include <functional>
#include <thread>
#include <vector>
#include <socks5/utils/non_copyable.hpp>

namespace socks5::utils {

class ThreadPool final : NonCopyable {
 public:
  using ThreadCb = std::function<void()>;
  using ThreadsVec = std::vector<std::jthread>;

  explicit ThreadPool(size_t threads_num);

  void SetThreadsNum(size_t threads_num) noexcept;
  size_t GetThreadsNum() const noexcept;
  void Run(ThreadCb thread_cb);
  void JoinAll();

 private:
  ThreadsVec threads_;
  size_t threads_num_;
};

}  // namespace socks5::utils