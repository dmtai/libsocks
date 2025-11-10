#pragma once

#include <functional>
#include <socks5/auth/server/config.hpp>
#include <memory>

namespace socks5::auth::server {

/**
 * @brief A callback that will be called for authentication.
 *
 * @param username login sent by the client for authentication.
 * @param pass password sent by the client for authentication.
 * @param config contains the specified login and password for authentication.
 * when configuring the proxy server.
 * @return true if authentication was successful, or false otherwier.
 */
using UserAuthCb = std::function<bool(
    std::string_view username, std::string_view pass, const Config& config)>;

using UserAuthCbPtr = std::shared_ptr<UserAuthCb>;

}  // namespace socks5::auth::server