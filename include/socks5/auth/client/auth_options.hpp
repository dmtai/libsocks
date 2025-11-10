#pragma once

#include <string>
#include <variant>
#include <array>
#include <optional>
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <socks5/common/api_macro.hpp>

namespace socks5::auth::client {

namespace detail {

constexpr size_t kMaxUsernameLen{256};
constexpr size_t kMaxPasswordLen{256};

}  // namespace detail

/**
 * @brief Authentication method.
 */
enum class SOCKS5_API AuthMethod {
  // No auth.
  kNone,
  // Login-password auth(RFC 1929).
  kUser,
};

struct SOCKS5_API NoneAuthOptions final {};

/**
 * @brief Parameters for AuthMethod::kUser(RFC 1929) authentication.
 */
struct SOCKS5_API UserAuthOptions final {
  const char* username;
  const char* password;
};

using NoneAuthOptionsOpt = std::optional<NoneAuthOptions>;
using UserAuthOptionsOpt = std::optional<UserAuthOptions>;

/**
 * @brief Authentication parameters set by the client for sending to the socks5
 * proxy server.
 */
class SOCKS5_API AuthOptions final {
 public:
  /**
   * @brief Add authentication method and its parameters.
   *
   * @tparam Method authentication method type.
   * @tparam Args parameters for selected authentication method.
   * @param args parameters for selected authentication method. const char* with
   * username and const char* with password for auth by login and password. 0
   * arguments if no authentication. For example:
   * AddAuthMethod<AuthMethod::kUser>("username", "password");
   * AddAuthMethod<AuthMethod::kNone>();
   * @return AuthOptions&
   * @throws std::exception
   */
  template <AuthMethod Method, typename... Args>
  AuthOptions& AddAuthMethod(Args&&... args) {
    if constexpr (Method == AuthMethod::kNone) {
      if (!no_auth_) {
        ++size_;
      }
      no_auth_ = NoneAuthOptions{};
    } else if constexpr (Method == AuthMethod::kUser) {
      static_assert(sizeof...(args) == 2, "Incorrect number of arguments");
      if (!user_auth_) {
        ++size_;
      }
      user_auth_ = UserAuthOptions{std::forward<Args>(args)...};
      if (std::strlen(user_auth_->username) > detail::kMaxUsernameLen) {
        --size_;
        user_auth_ = std::nullopt;
        throw std::runtime_error{
            "The username length must be no more than 256 characters."};
      }
      if (std::strlen(user_auth_->password) > detail::kMaxPasswordLen) {
        --size_;
        user_auth_ = std::nullopt;
        throw std::runtime_error{
            "The password length must be no more than 256 characters."};
      }
    } else {
      static_assert(false, "Unknown auth method");
    }
    return *this;
  }

  /**
   * @brief AuthMethod::kNone parameters if AuthMethod::kNone is added.
   */
  const NoneAuthOptionsOpt& NoneAuth() const noexcept { return no_auth_; }

  /**
   * @brief AuthMethod::kUser parameters if AuthMethod::kUser is added.
   */
  const UserAuthOptionsOpt& UserAuth() const noexcept { return user_auth_; }

  /**
   * @brief Number of added authentication methods.
   */
  uint8_t Size() const noexcept { return size_; }

 private:
  uint8_t size_{};
  NoneAuthOptionsOpt no_auth_;
  UserAuthOptionsOpt user_auth_;
};

[[nodiscard]] SOCKS5_API AuthOptions MakeAuthOptions() noexcept;

}  // namespace socks5::auth::client