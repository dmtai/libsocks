#include <gtest/gtest.h>
#include <socks5/auth/client/auth_options.hpp>
#include <string>

namespace socks5::auth::client {

TEST(AuthOptionsTest, DefaultConstruction) {
  AuthOptions options;
  EXPECT_EQ(options.Size(), 0);
  EXPECT_FALSE(options.NoneAuth().has_value());
  EXPECT_FALSE(options.UserAuth().has_value());
}

TEST(AuthOptionsTest, AddNoneAuth) {
  AuthOptions options;
  options.AddAuthMethod<AuthMethod::kNone>();

  EXPECT_EQ(options.Size(), 1);
  EXPECT_TRUE(options.NoneAuth().has_value());
  EXPECT_FALSE(options.UserAuth().has_value());
}

TEST(AuthOptionsTest, AddUserAuthValid) {
  AuthOptions options;
  options.AddAuthMethod<AuthMethod::kUser>("test_user", "test_pass");

  EXPECT_EQ(options.Size(), 1);
  EXPECT_FALSE(options.NoneAuth().has_value());
  ASSERT_TRUE(options.UserAuth().has_value());
  EXPECT_STREQ(options.UserAuth()->username, "test_user");
  EXPECT_STREQ(options.UserAuth()->password, "test_pass");
}

TEST(AuthOptionsTest, AddUserAuthLongUsername) {
  std::string long_username(detail::kMaxUsernameLen + 1, 'a');
  AuthOptions options;

  EXPECT_THROW(
      {
        options.AddAuthMethod<AuthMethod::kUser>(long_username.c_str(),
                                                 "valid_pass");
      },
      std::runtime_error);

  EXPECT_EQ(options.Size(), 0);
  EXPECT_FALSE(options.UserAuth().has_value());
}

TEST(AuthOptionsTest, AddUserAuthLongPassword) {
  std::string long_password(detail::kMaxPasswordLen + 1, 'b');
  AuthOptions options;

  EXPECT_THROW(
      {
        options.AddAuthMethod<AuthMethod::kUser>("valid_user",
                                                 long_password.c_str());
      },
      std::runtime_error);

  EXPECT_EQ(options.Size(), 0);
  EXPECT_FALSE(options.UserAuth().has_value());
}

TEST(AuthOptionsTest, AddNoneAuthTwice) {
  AuthOptions options;
  options.AddAuthMethod<AuthMethod::kNone>();
  options.AddAuthMethod<AuthMethod::kNone>();

  EXPECT_EQ(options.Size(), 1);
  EXPECT_TRUE(options.NoneAuth().has_value());
}

TEST(AuthOptionsTest, AddUserAuthTwiceUpdatesData) {
  AuthOptions options;
  options.AddAuthMethod<AuthMethod::kUser>("user1", "pass1");
  options.AddAuthMethod<AuthMethod::kUser>("user2", "pass2");

  EXPECT_EQ(options.Size(), 1);
  ASSERT_TRUE(options.UserAuth().has_value());
  EXPECT_STREQ(options.UserAuth()->username, "user2");
  EXPECT_STREQ(options.UserAuth()->password, "pass2");
}

TEST(AuthOptionsTest, AddBothMethods) {
  AuthOptions options;
  options.AddAuthMethod<AuthMethod::kNone>();
  options.AddAuthMethod<AuthMethod::kUser>("both_user", "both_pass");

  EXPECT_EQ(options.Size(), 2);
  EXPECT_TRUE(options.NoneAuth().has_value());
  ASSERT_TRUE(options.UserAuth().has_value());
  EXPECT_STREQ(options.UserAuth()->username, "both_user");
  EXPECT_STREQ(options.UserAuth()->password, "both_pass");
}

TEST(AuthOptionsTest, MakeAuthOptionsFunction) {
  auto options = MakeAuthOptions();
  EXPECT_EQ(options.Size(), 0);
  EXPECT_FALSE(options.NoneAuth().has_value());
  EXPECT_FALSE(options.UserAuth().has_value());
}

}  // namespace socks5::auth::client