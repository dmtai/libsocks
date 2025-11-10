#pragma once

#include <socks5/common/datagram_buffer.hpp>
#include <common/defs.hpp>
#include <socks5/common/asio.hpp>
#include <socks5/common/address.hpp>

namespace socks5::common {

namespace detail {

constexpr size_t kDatagramBuffsCount{3};

}  // namespace detail

// The first buffer is the first 2 fields of proto::DatagramHeader, the second
// buffer is the address, 3 is the data to send.
using DatagramBuffs =
    std::array<asio::const_buffer, detail::kDatagramBuffsCount>;

/**
 * @brief Creates a serialized socks5 datagram into 3 asio::const_buffer.
 */
DatagramBuffs MakeDatagramBuffs(const common::Address& target_server_addr,
                                const char* data, size_t size) noexcept;

DatagramBuffs MakeDatagramBuffs(const utils::Buffer& target_server_addr_buf,
                                const char* data, size_t size) noexcept;

/**
 * @brief Packs the data into a socks5 datagram and sends it.
 */
BytesCountOrErrorAwait SendTo(udp::socket& socket,
                              const udp::endpoint& proxy_server_ep,
                              const common::Address& target_server_addr,
                              const char* data, size_t size) noexcept;

/**
 * @brief Receives a socks5 datagram and unpacks it.
 */
BytesCountOrErrorAwait ReceiveFrom(udp::socket& socket,
                                   udp::endpoint& proxy_sender_ep,
                                   common::Address& sender_addr,
                                   common::DatagramBuffer& buf) noexcept;

}  // namespace socks5::common