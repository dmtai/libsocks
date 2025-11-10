#include <net/connection_error.hpp>

namespace socks5::net {

ConnectionError::ConnectionError(std::string_view hdr) noexcept
    : hdr_{std::move(hdr)} {}

std::string ConnectionError::Msg() const noexcept {
  try {
    return std::visit([this](const auto& err) { return MakeMsg(err); }, error_);
  } catch (const std::exception& ex) {
    return ex.what();
  }
}

std::string ConnectionError::MakeMsg(
    const boost::system::error_code& err) const {
  return fmt::format("{}. msg={}", hdr_, err.message());
}

std::string ConnectionError::MakeMsg(std::exception_ptr err) const {
  return fmt::format("{}. msg={}", hdr_, GetExceptionMsg(err));
}

std::string ConnectionError::MakeMsg(
    [[maybe_unused]] std::monostate err) const {
  return fmt::format("{}", hdr_);
}

const char* ConnectionError::GetExceptionMsg(
    std::exception_ptr err) const noexcept {
  try {
    if (err) std::rethrow_exception(err);
  } catch (const std::exception& ex) {
    return ex.what();
  }
  return {};
}

ConnectionError MakeError(std::string_view hdr) noexcept { return {hdr}; }

}  // namespace socks5::net