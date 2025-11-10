#include <server/tcp_relay.hpp>
#include <utils/timeout.hpp>
#include <common/addr_utils.hpp>
#include <net/utils.hpp>
#include <socks5/common/asio.hpp>
#include <server/relay_data_processors.hpp>
#include <server/sent_relay_data.hpp>
#include <socks5/utils/watchdog.hpp>

namespace socks5::server {

namespace {

#ifdef SOCKS5_TCP_RELAY_BUF_SIZE
constexpr size_t kRelayBufSize{SOCKS5_TCP_RELAY_BUF_SIZE};
#else
constexpr size_t kRelayBufSize{16384};
#endif

VoidAwait Relay(net::TcpConnection& from, net::TcpConnection& to,
                utils::Watchdog& watchdog) noexcept {
  utils::StaticBuffer<kRelayBufSize> buf;
  for (;;) {
    watchdog.Update();
    if (const auto err = co_await from.ReadSome(buf)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, from));
      co_return;
    }
    watchdog.Update();
    if (const auto err = co_await to.Send(buf)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, to));
      co_return;
    }
    buf.Clear();
  }
}

class RelayWithDataProcessor final {
 public:
  RelayWithDataProcessor(
      const tcp::endpoint& from_ep, const tcp::endpoint& to_ep,
      net::TcpConnection& from, net::TcpConnection& to,
      utils::Watchdog& watchdog,
      const TcpRelayDataProcessorCreatorCb& data_processor_creator) noexcept
      : from_ep_{from_ep},
        to_ep_{to_ep},
        from_{from},
        to_{to},
        watchdog_{watchdog},
        data_processor_{data_processor_creator(from_ep_, to_ep_)} {}

  VoidAwait Relay() {
    sent_data_.Clear();
    buf_.Clear();
    for (;;) {
      watchdog_.Update();
      if (const auto err = co_await from_.ReadSome(buf_)) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, from_));
        co_return;
      }
      watchdog_.Update();
      data_processor_(
          buf_.BeginRead(), buf_.ReadableBytes(),
          [&](const char* data, size_t size) { SendToBuf(data, size); });
      watchdog_.Update();
      if (!co_await sent_data_.ForEach(
              [&](const RelayData& relay_data) noexcept -> BoolAwait {
                co_return co_await SendToNet(std::move(relay_data));
              })) {
        co_return;
      }
      sent_data_.Clear();
      buf_.Clear();
    }
  }

 private:
  void SendToBuf(const char* data, size_t size) { sent_data_.Send(data, size); }

  BoolAwait SendToNet(const RelayData& relay_data) noexcept {
    watchdog_.Update();
    if (const auto err =
            co_await to_.Send(relay_data.first, relay_data.second)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, to_));
      co_return false;
    }
    co_return true;
  }

  const tcp::endpoint& from_ep_;
  const tcp::endpoint& to_ep_;
  net::TcpConnection& from_;
  net::TcpConnection& to_;
  utils::Watchdog& watchdog_;
  const TcpRelayDataProcessorCb data_processor_;
  SentRelayData sent_data_;
  utils::StaticBuffer<kRelayBufSize> buf_;
};

VoidAwait RunRelayWithDataProcessor(
    const tcp::endpoint& from_ep, const tcp::endpoint& to_ep,
    net::TcpConnection& from, net::TcpConnection& to, utils::Watchdog& watchdog,
    const TcpRelayDataProcessorCreatorCb& data_processor_creator) {
  try {
    RelayWithDataProcessor relay_with_data_processor{
        from_ep, to_ep, from, to, watchdog, data_processor_creator};
    co_await relay_with_data_processor.Relay();
  } catch (const std::exception& ex) {
    SOCKS5_LOG(debug, "Tcp relay exception. From: {}. To: {}. {}",
               net::ToString(from), net::ToString(to), ex.what());
  }
}

}  // namespace

VoidAwait DefaultTcpRelayHandler(net::TcpConnection from, net::TcpConnection to,
                                 const Config& config) {
  SOCKS5_LOG(debug, "Tcp relay started. Client: {}. Server: {}",
             net::ToString(from), net::ToString(to));
  try {
    utils::Watchdog watchdog{co_await asio::this_coro::executor,
                             config.tcp_relay_timeout};
    co_await (Relay(from, to, watchdog) || Relay(to, from, watchdog) ||
              watchdog.Run());
  } catch (const std::exception&) {
    SOCKS5_LOG(debug,
               "Tcp relay finished with exception. Client: {}. Server: {}",
               net::ToString(from), net::ToString(to));
    throw;
  }
  SOCKS5_LOG(debug, "Tcp relay finished. Client: {}. Server: {}",
             net::ToString(from), net::ToString(to));
}

VoidAwait TcpRelayHandlerWithDataProcessor(
    net::TcpConnection from, net::TcpConnection to, const Config& config,
    const TcpRelayDataProcessor& tcp_relay_data_processor) {
  SOCKS5_LOG(debug, "Tcp relay started. Client: {}. Server: {}",
             net::ToString(from), net::ToString(to));
  const auto [from_err, from_ep] = from.RemoteEndpoint();
  if (from_err) {
    SOCKS5_LOG(debug, net::MakeErrorMsg(*from_err, from));
    co_return;
  }
  const auto [to_err, to_ep] = to.RemoteEndpoint();
  if (to_err) {
    SOCKS5_LOG(debug, to_err->Msg());
    co_return;
  }
  try {
    utils::Watchdog watchdog{co_await asio::this_coro::executor,
                             config.tcp_relay_timeout};
    co_await (
        RunRelayWithDataProcessor(*from_ep, *to_ep, from, to, watchdog,
                                  tcp_relay_data_processor.client_to_server) ||
        RunRelayWithDataProcessor(*to_ep, *from_ep, to, from, watchdog,
                                  tcp_relay_data_processor.server_to_client) ||
        watchdog.Run());
  } catch (const std::exception&) {
    SOCKS5_LOG(debug, "Tcp relay finished. Client: {}. Server: {}",
               net::ToString(from), net::ToString(to));
    throw;
  }
  SOCKS5_LOG(debug, "Tcp relay finished. Client: {}. Server: {}",
             net::ToString(from), net::ToString(to));
}

}  // namespace socks5::server