#pragma once

#include <boost/system/error_code.hpp>
#include <utility>

namespace socks5::utils {

template <typename T>
using ErrorOr = std::pair<boost::system::error_code, T>;

}  // namespace socks5::utils