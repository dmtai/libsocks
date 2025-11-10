#include <gtest/gtest.h>
#include <utils/thread_pool.hpp>

namespace socks5::utils {

TEST(ThreadPoolTest, InvalidThreadCountOnCreation) {
  EXPECT_THROW(ThreadPool pool(0), std::runtime_error);
}

TEST(ThreadPoolTest, SetAndGetThreadCount) {
  ThreadPool pool{2};
  EXPECT_EQ(pool.GetThreadsNum(), 2);

  pool.SetThreadsNum(5);
  EXPECT_EQ(pool.GetThreadsNum(), 5);

  pool.SetThreadsNum(1);
  EXPECT_EQ(pool.GetThreadsNum(), 1);
}

TEST(ThreadPoolTest, RunTasks) {
  constexpr size_t kThreadCount{4};
  ThreadPool pool{kThreadCount};

  std::atomic<int> counter{};
  auto task = [&counter]() { counter.fetch_add(1, std::memory_order_relaxed); };

  pool.Run(task);
  pool.JoinAll();

  EXPECT_EQ(counter.load(), kThreadCount);
}

TEST(ThreadPoolTest, RunMultipleTimes) {
  ThreadPool pool{3};

  std::atomic<int> first_counter{};
  pool.Run([&first_counter]() { first_counter.fetch_add(1); });
  pool.JoinAll();
  EXPECT_EQ(first_counter.load(), 3);

  std::atomic<int> second_counter{0};
  pool.Run([&second_counter]() { second_counter.fetch_add(1); });
  pool.JoinAll();
  EXPECT_EQ(second_counter.load(), 3);
}

TEST(ThreadPoolTest, RunBlocksUntilPreviousComplete) {
  ThreadPool pool{1};

  std::mutex mutex;
  std::condition_variable cv;
  bool task_started{false};
  bool allow_finish{false};

  auto long_task = [&]() {
    {
      std::lock_guard lk{mutex};
      task_started = true;
    }
    cv.notify_one();

    std::unique_lock lk{mutex};
    cv.wait(lk, [&allow_finish] { return allow_finish; });
  };

  pool.Run(long_task);

  {
    std::unique_lock lk{mutex};
    cv.wait(lk, [&task_started] { return task_started; });
  }

  std::atomic<bool> new_task_started{false};
  std::thread runner(
      [&]() { pool.Run([&new_task_started]() { new_task_started = true; }); });

  EXPECT_FALSE(new_task_started);

  {
    std::lock_guard lk{mutex};
    allow_finish = true;
  }
  cv.notify_all();

  if (runner.joinable()) {
    runner.join();
  }

  pool.JoinAll();
  EXPECT_TRUE(new_task_started);
}

TEST(ThreadPoolTest, JoinsThreadsOnDestruction) {
  std::atomic<bool> task_finished{false};

  {
    ThreadPool pool{1};
    pool.Run([&task_finished]() {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
      task_finished = true;
    });
  }

  EXPECT_TRUE(task_finished);
}

}  // namespace socks5::utils
