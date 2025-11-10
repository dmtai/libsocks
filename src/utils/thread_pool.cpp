#include <utils/thread_pool.hpp>
#include <stdexcept>

namespace socks5::utils {

ThreadPool::ThreadPool(size_t threads_num) : threads_num_{threads_num} {
  if (threads_num_ == 0) {
    throw std::runtime_error{
        "The number of threads in the thread pool must be greater than 0"};
  }
}

void ThreadPool::SetThreadsNum(size_t threads_num) noexcept {
  threads_num_ = threads_num;
}

size_t ThreadPool::GetThreadsNum() const noexcept { return threads_num_; }

void ThreadPool::JoinAll() {
  for (auto& thread : threads_) {
    if (!thread.joinable()) {
      continue;
    }
    thread.join();
  }
}

void ThreadPool::Run(ThreadCb thread_cb) {
  threads_.clear();
  for (size_t i = 0; i < threads_num_; ++i) {
    threads_.emplace_back(thread_cb);
  }
}

}  // namespace socks5::utils