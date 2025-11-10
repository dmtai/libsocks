#pragma once

#include <gtest/gtest.h>
#include <coroutine>

class CoroutineAssertionException : public std::exception {};

inline void CheckCoroutineAssertion(bool condition, const char* expression) {
  if (!condition) {
    ADD_FAILURE() << "Assertion failed: " << expression;
    throw CoroutineAssertionException();
  }
}

#define CO_ASSERT_EQ(val1, val2)                                               \
  do {                                                                         \
    auto _val1 = (val1);                                                       \
    auto _val2 = (val2);                                                       \
    if (!::testing::internal::EqHelper::Compare(#val1, #val2, _val1, _val2)) { \
      ADD_FAILURE() << "Expected equality of these values: " << #val1          \
                    << " and " << #val2;                                       \
      throw CoroutineAssertionException();                                     \
    }                                                                          \
  } while (0)

#define CO_ASSERT_TRUE(condition)                           \
  do {                                                      \
    if (!(condition)) {                                     \
      ADD_FAILURE() << "Value of: " << #condition           \
                    << "\n  Actual: false\nExpected: true"; \
      throw CoroutineAssertionException();                  \
    }                                                       \
  } while (0)

#define CO_ASSERT_FALSE(condition)                          \
  do {                                                      \
    if (condition) {                                        \
      ADD_FAILURE() << "Value of: " << #condition           \
                    << "\n  Actual: true\nExpected: false"; \
      throw CoroutineAssertionException();                  \
    }                                                       \
  } while (0)

template <typename Promise>
void RunCoroutineTest(std::coroutine_handle<Promise> coroutine) {
  try {
    coroutine.resume();
    if (!coroutine.done()) {
      ADD_FAILURE() << "Coroutine did not complete synchronously";
    }
  } catch (const CoroutineAssertionException&) {
  }
}