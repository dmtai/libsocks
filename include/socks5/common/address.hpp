#pragma once

#include <string>
#include <socks5/utils/fast_pimpl.hpp>
#include <socks5/proto/proto_fwd.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/utils/buffer.hpp>
#include <socks5/common/api_macro.hpp>

namespace socks5::common {

/**
 * @brief Contains an IPv4/IPv6 address or domain name.
 */
class SOCKS5_API Address final {
 public:
  friend bool operator==(const Address& lhs, const Address& rhs) noexcept;

  /**
   * @brief Construct a new empty Address object.
   */
  Address() noexcept;

  /**
   * @brief Construct a new Address object from a string containing IPv4/IPv6
   * address or domain name and port.
   *
   * @param addr IPv4/IPv6 address as a string or domain name.
   * @param port address port.
   * @throws std::exception
   */
  Address(std::string_view addr, unsigned short port);

  /**
   * @brief Construct a new Address object from asio::tcp::endpoint.
   *
   * @param ep tcp::endpoint with address.
   * @throws std::exception
   */
  explicit Address(const tcp::endpoint& ep);

  /**
   * @brief Construct a new Address object from asio::udp::endpoint.
   *
   * @param ep udp::endpoint with address.
   * @throws std::exception
   */
  explicit Address(const udp::endpoint& ep);

  explicit Address(proto::Addr other) noexcept;
  Address(const Address& other) noexcept;
  Address& operator=(const Address& other) noexcept;
  Address(Address&& other) noexcept;
  Address& operator=(Address&& other) noexcept;
  ~Address();

  /**
   * @brief Check if address is IPv4/IPv6.
   */
  bool IsIP() const noexcept;

  /**
   * @brief Check if address is domain name.
   */
  bool IsDomain() const noexcept;

  /**
   * @brief Check if address is empty.
   */
  bool IsEmpty() const noexcept;

  /**
   * @brief Get port in host byte order.
   *
   * @return std::nullopt<unsigned short> with a port or std::nullopt if the
   * Address is empty.
   */
  std::optional<unsigned short> Port() const noexcept;

  /**
   * @brief Get a string with an address in the format 'ip/domain:port'.
   *
   * @throws std::exception
   */
  std::string ToString() const;

  proto::Addr ToProtoAddr() const noexcept;
  const utils::Buffer& Serialize() const noexcept;

  /**
   * @brief Get domain name from Address with domain name.
   *
   * @return std::optional<std::string_view> with domain name or std::nullopt.
   */
  std::optional<std::string_view> ToDomain() const noexcept;

  /**
   * @brief Convert IPv4/IPv6 address to asio endpoint. The domain name isn't
   * convertible.
   *
   * @return asio::tcp/asio::udp endpoint
   * @throws std::exception
   */
  template <typename T>
  T::endpoint ToEndpoint() const;

 private:
  struct Impl;
  constexpr static size_t kSize{304};
  constexpr static size_t kAlignment{8};
  utils::FastPimpl<Impl, kSize, kAlignment> impl_;
};

bool operator==(const Address& lhs, const Address& rhs) noexcept;

}  // namespace socks5::common
