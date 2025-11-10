#include <gtest/gtest.h>
#include <net/connection_error.hpp>
#include <socks5/common/asio.hpp>
#include <stdexcept>
#include <string>

namespace socks5::net {

TEST(ConnectionErrorTest, DefaultConstructorWithHeader) {
  const ConnectionError error{"Test Header"};
  EXPECT_EQ(error.Msg(), "Test Header");
}

TEST(ConnectionErrorTest, ErrorCodeConstruction) {
  const boost::system::error_code ec{boost::asio::error::connection_refused};
  const ConnectionError error{"Connection failed", ec};

  EXPECT_NE(error.Msg().find("Connection failed"), std::string::npos);
}

TEST(ConnectionErrorTest, ExceptionConstruction) {
  std::exception_ptr ex;
  try {
    throw std::runtime_error("Test exception message");
  } catch (...) {
    ex = std::current_exception();
  }

  const ConnectionError error{"Operation failed", ex};
  const auto msg = error.Msg();

  EXPECT_NE(msg.find("Operation failed"), std::string::npos);
}

TEST(ConnectionErrorTest, MakeErrorWithHeaderOnly) {
  const auto error = MakeError("Simple error");
  EXPECT_EQ(error.Msg(), "Simple error");
}

TEST(ConnectionErrorTest, MakeErrorWithErrorCode) {
  const auto ec = boost::asio::error::timed_out;
  const auto error = MakeError("Timeout error", ec);

  EXPECT_NE(error.Msg().find("Timeout error"), std::string::npos);
  EXPECT_NE(error.Msg().find("msg="), std::string::npos);
}

TEST(ConnectionErrorTest, MakeErrorWithException) {
  std::exception_ptr ex;
  try {
    throw std::logic_error{"Invalid operation"};
  } catch (...) {
    ex = std::current_exception();
  }

  const auto error = MakeError("Logic failure", ex);
  const auto msg = error.Msg();

  EXPECT_NE(msg.find("Logic failure"), std::string::npos);
}

TEST(ConnectionErrorTest, MessageFormattingWithMonostate) {
  const ConnectionError error{"Header only"};
  EXPECT_EQ(error.Msg(), "Header only");
}

TEST(ConnectionErrorTest, NestedExceptionHandling) {
  std::exception_ptr nested_ex;
  try {
    try {
      throw std::out_of_range{"Index out of range"};
    } catch (...) {
      std::throw_with_nested(std::runtime_error{"Wrapper error"});
    }
  } catch (...) {
    nested_ex = std::current_exception();
  }

  const ConnectionError error{"Nested error", nested_ex};
  const auto msg = error.Msg();

  EXPECT_NE(msg.find("Nested error"), std::string::npos);
}

}  // namespace socks5::net
