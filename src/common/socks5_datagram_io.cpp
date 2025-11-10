#include <common/socks5_datagram_io.hpp>
#include <socks5/error/error.hpp>
#include <serializers/serializers.hpp>
#include <common/proto_builders.hpp>
#include <net/io.hpp>
#include <common/socks5_datagram_validator.hpp>
#include <parsers/parsers.hpp>

namespace socks5::common {

namespace {

// Size of first 2 fields of proto::DatagramHeader.
constexpr size_t kDatagramFirst2FieldsSize{3};

using DatagramFirst2FieldsArray = std::array<char, kDatagramFirst2FieldsSize>;

constexpr DatagramFirst2FieldsArray datagramFirst2FieldsArray{};

}  // namespace

DatagramBuffs MakeDatagramBuffs(const common::Address& target_server_addr,
                                const char* data, size_t size) noexcept {
  const auto& addr_buf = target_server_addr.Serialize();
  return MakeDatagramBuffs(addr_buf, data, size);
}

DatagramBuffs MakeDatagramBuffs(const utils::Buffer& target_server_addr_buf,
                                const char* data, size_t size) noexcept {
  DatagramBuffs buffs;
  buffs[0] = boost::asio::buffer(datagramFirst2FieldsArray);
  buffs[1] = boost::asio::buffer(target_server_addr_buf.BeginRead(),
                                 target_server_addr_buf.ReadableBytes());
  buffs[2] = boost::asio::buffer(data, size);
  return buffs;
}

BytesCountOrErrorAwait SendTo(udp::socket& socket,
                              const udp::endpoint& proxy_server_ep,
                              const common::Address& target_server_addr,
                              const char* data, size_t size) noexcept {
  if (target_server_addr.IsEmpty()) {
    co_return std::make_pair(error::Error::kInvalidAddress, 0);
  }
  const auto buffs = MakeDatagramBuffs(target_server_addr, data, size);
  const auto [err, sent_bytes] = co_await socket.async_send_to(
      buffs, proxy_server_ep, use_nothrow_awaitable);
  co_return std::make_pair(std::move(err), sent_bytes);
}

BytesCountOrErrorAwait ReceiveFrom(udp::socket& socket,
                                   udp::endpoint& proxy_sender_ep,
                                   common::Address& sender_addr,
                                   DatagramBuffer& dgrm_buf) noexcept {
  utils::Buffer buf{dgrm_buf.BufData(), dgrm_buf.BufSize()};
  const auto err = co_await net::Read(socket, proxy_sender_ep, buf);
  if (err) {
    co_return std::make_pair(std::move(err), 0);
  }
  if (!common::ValidateDatagramLength(buf)) {
    co_return std::make_pair(error::Error::kInvalidDatagram, 0);
  }
  auto datagram = parsers::ParseDatagram(buf);
  sender_addr = common::Address{std::move(datagram.header.addr)};
  dgrm_buf.SetHeader(buf.ReadableBytes() - datagram.data.data_size);
  dgrm_buf.SetBody(reinterpret_cast<char*>(datagram.data.data),
                   datagram.data.data_size);
  co_return std::make_pair(error::Error::kSucceeded, datagram.data.data_size);
}

}  // namespace socks5::common