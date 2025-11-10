#include <utils/timeout.hpp>
#include <common/addr_utils.hpp>
#include <net/utils.hpp>
#include <socks5/utils/buffer.hpp>
#include <proto/proto.hpp>
#include <server/udp_relay.hpp>
#include <parsers/parsers.hpp>
#include <serializers/serializers.hpp>
#include <common/defs.hpp>
#include <server/sent_relay_data.hpp>
#include <net/connection_error.hpp>
#include <common/proto_builders.hpp>
#include <common/socks5_datagram_validator.hpp>
#include <common/socks5_datagram_io.hpp>
#include <socks5/utils/watchdog.hpp>

namespace socks5::server {

namespace {

struct TargetServerData final {
  // Connection for recv/send data to target server.
  net::UdpConnection connect;
  // Target server address.
  udp::endpoint ep;
  // Targert server serialized address.
  AddrBuf addr;
};

using TargetServerDataRef = std::reference_wrapper<TargetServerData>;
using TargetServer = std::pair<AddrConstRef, TargetServerDataRef>;
using TargetServerOpt = std::optional<TargetServer>;
using TargetServerOptAwait = asio::awaitable<TargetServerOpt>;
using TargetServers = std::unordered_map<proto::Addr, TargetServerData,
                                         common::Hash, common::EqualTo>;
using DatagramOrError = std::pair<net::UdpConnectErrorOpt, DatagramOpt>;
using DatagramOrErrorAwait = asio::awaitable<DatagramOrError>;

constexpr size_t kTcpBufSize{4096};

template <typename Derived>
class HandlerBase : utils::NonCopyable {
 public:
  HandlerBase(net::TcpConnection client, net::UdpConnection proxy,
              const proto::Addr& client_addr, utils::Watchdog& watchdog,
              const Config& config, common::Metrics& metrics) noexcept
      : client_{std::move(client)},
        proxy_{std::move(proxy)},
        expected_client_ep_{net::MakeEndpointFromIP<udp>(client_addr)},
        watchdog_{watchdog},
        config_{config},
        metrics_{metrics} {}

  VoidAwait ProcessTcp() noexcept {
    utils::StaticBuffer<kTcpBufSize> buf;
    for (;;) {
      if (const auto err = co_await client_.ReadSome(buf)) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, client_));
        co_return;
      }
      buf.Clear();
    }
  }

  const std::string& ProxyAddrStr() noexcept { return net::ToString(proxy_); }

  std::string ClientAddrStr() const {
    if (client_ep_) {
      return net::ToString<udp>(*client_ep_);
    }
    return "unknown";
  }

 protected:
  template <typename Buffer>
  DatagramOrErrorAwait RecvClientDatagram(Buffer& buf) noexcept {
    watchdog_.Update();
    const auto [err, sender_ep] = co_await proxy_.Read(buf);
    if (err) {
      co_return std::make_pair(std::move(err), std::nullopt);
    }
    if (!VerifyDatagramSender(*sender_ep)) {
      co_return std::make_pair(std::nullopt, std::nullopt);
    }
    // The first verified client address is saved and used in the future for
    // relaying and verification.
    if (!client_ep_) {
      client_ep_ = sender_ep;
      expected_client_ep_ = std::move(*sender_ep);
    }
    if (!common::ValidateDatagramLength(buf)) {
      co_return std::make_pair(std::nullopt, std::nullopt);
    }
    const auto datagram = parsers::ParseDatagram(buf);
    if (datagram.header.frag != proto::UdpFrag::kUdpFragNoFrag) {
      co_return std::make_pair(std::nullopt, std::nullopt);
    }
    co_return std::make_pair(std::nullopt, std::move(datagram));
  }

  TargetServerOptAwait FindOrMakeTargetServer(
      const proto::Addr& addr) noexcept {
    try {
      if (auto target_server = GetTargetServer(addr)) {
        co_return target_server;
      }
      auto connect = net::MakeUdpConnect(
          net::MakeOpenSocket<udp>(co_await asio::this_coro::executor,
                                   config_.listener_addr.first, 0),
          metrics_);
      const auto [err, ep] = co_await net::MakeEndpoint<udp>(addr);
      if (err) {
        SOCKS5_LOG(debug,
                   "Udp relay. Endpoint error. Proxy: {}. Client: {}. Target: "
                   "{}. msg={}",
                   net::ToString(proxy_), net::ToString<udp>(*client_ep_),
                   common::ToString(addr), err.message());
        co_return std::nullopt;
      }
      auto target_server = AddTargetServer(addr, std::move(connect), *ep);
      SOCKS5_LOG(debug,
                 "Udp relay. Added new target server. Proxy: {}. Client: {}. "
                 "Target server: {}",
                 net::ToString(proxy_), net::ToString<udp>(*client_ep_),
                 net::ToString(target_server.second.get().connect));
      reinterpret_cast<Derived*>(this)->RunTargetServerHandler(
          co_await asio::this_coro::executor, target_server);
      co_return target_server;
    } catch (const std::exception& ex) {
      SOCKS5_LOG(error, "Udp relay exception. {}", ex.what());
      co_return std::nullopt;
    }
  }

  TargetServer AddTargetServer(const proto::Addr& addr,
                               net::UdpConnection&& connect, udp::endpoint ep) {
    const auto it = target_servers_.insert(
        {addr, TargetServerData{std::move(connect), std::move(ep),
                                serializers::Serialize(addr)}});
    return std::make_pair(std::ref(it.first->first),
                          std::ref(it.first->second));
  }

  TargetServerOpt GetTargetServer(const proto::Addr& addr) {
    const auto it = target_servers_.find(addr);
    if (it != target_servers_.end()) {
      return std::make_pair(std::ref(it->first), std::ref(it->second));
    }
    return std::nullopt;
  }

  bool VerifyDatagramSender(const udp::endpoint& accepted_sender) noexcept {
    if (expected_client_ep_.address() != accepted_sender.address()) {
      SOCKS5_LOG(debug,
                 "UDP relay. The datagram sender address doesn't match the "
                 "UDP ASSOCIATE client address. Proxy: {}. Expected client: "
                 "{}. Sender: {}",
                 net::ToString(proxy_), net::ToString<udp>(expected_client_ep_),
                 net::ToString<udp>(accepted_sender));
      return false;
    }
    const auto client_ep_port = expected_client_ep_.port();
    if (client_ep_port != 0) {
      if (client_ep_port != accepted_sender.port()) {
        SOCKS5_LOG(debug,
                   "UDP relay. The datagram sender address doesn't match the "
                   "UDP ASSOCIATE client address. Proxy: {}. Expected client: "
                   "{}. Sender: {}",
                   net::ToString(proxy_),
                   net::ToString<udp>(expected_client_ep_),
                   net::ToString<udp>(accepted_sender));
        return false;
      }
    }
    return true;
  }

  void Stop() noexcept {
    for (auto& target_server : target_servers_) {
      target_server.second.connect.Stop();
    }
    client_.Stop();
    proxy_.Stop();
  }

  net::TcpConnection client_;
  net::UdpConnection proxy_;
  udp::endpoint expected_client_ep_;
  UdpEndpointOpt client_ep_;
  utils::Watchdog& watchdog_;
  TargetServers target_servers_;
  const Config& config_;
  common::Metrics& metrics_;
};

class Handler final : public HandlerBase<Handler>,
                      public std::enable_shared_from_this<Handler> {
 public:
  using HandlerBase<Handler>::HandlerBase;
  friend HandlerBase<Handler>;

  VoidAwait ProcessUdp() noexcept {
    utils::StaticBuffer<kDatagramMaxLen> buf;
    for (;;) {
      buf.Clear();
      const auto [err, datagram] = co_await RecvClientDatagram(buf);
      if (err) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, proxy_));
        co_return Stop();
      }
      if (!datagram) {
        continue;
      }
      auto target_server =
          co_await FindOrMakeTargetServer(datagram->header.addr);
      if (!target_server) {
        co_return Stop();
      }
      auto& target_server_data = target_server->second.get();
      watchdog_.Update();
      if (const auto err = co_await target_server_data.connect.Send(
              target_server_data.ep,
              reinterpret_cast<const char*>(datagram->data.data),
              datagram->data.data_size)) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, target_server_data.connect));
        co_return Stop();
      }
    }
  }

 private:
  VoidAwait ProcessTargetServer(TargetServer target_server) noexcept {
    utils::StaticBuffer<kDatagramMaxLen> buf;
    auto& target_server_data = target_server.second.get();
    for (;;) {
      buf.Clear();
      watchdog_.Update();
      const auto [err, sender_ep] =
          co_await target_server_data.connect.Read(buf);
      if (err) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, target_server_data.connect));
        proxy_.Cancel();
        co_return;
      }
      if (target_server_data.ep != *sender_ep) {
        continue;
      }
      const auto buffs =
          common::MakeDatagramBuffs(utils::MakeBuffer(target_server_data.addr),
                                    buf.Begin(), buf.ReadableBytes());
      watchdog_.Update();
      if (const auto err = co_await proxy_.Send(*client_ep_, buffs)) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, proxy_));
        proxy_.Cancel();
        co_return;
      }
    }
  }

  void RunTargetServerHandler(const asio::any_io_executor& executor,
                              TargetServer target_server) {
    asio::co_spawn(
        executor,
        [self = this->shared_from_this(), target_server, this] {
          return ProcessTargetServer(std::move(target_server));
        },
        asio::detached);
  }
};

class HandlerWithDataProcessor final
    : public HandlerBase<HandlerWithDataProcessor>,
      public std::enable_shared_from_this<HandlerWithDataProcessor> {
 public:
  friend HandlerBase<HandlerWithDataProcessor>;

  HandlerWithDataProcessor(net::TcpConnection client, net::UdpConnection proxy,
                           const proto::Addr& client_addr,
                           utils::Watchdog& watchdog, const Config& config,
                           common::Metrics& metrics,
                           const UdpRelayDataProcessor& data_processor) noexcept
      : HandlerBase<HandlerWithDataProcessor>(
            std::move(client), std::move(proxy), client_addr, watchdog,
            std::move(config), metrics),
        udp_relay_data_processor_{data_processor} {}

  VoidAwait ProcessUdp() noexcept {
    try {
      const auto data_processor =
          udp_relay_data_processor_.client_to_server(expected_client_ep_);
      co_await RelayDataFromClient(data_processor);
    } catch (const std::exception& ex) {
      SOCKS5_LOG(
          debug, "Udp relay exception. Proxy: {}. Client: {}. {}",
          net::ToString(proxy_),
          net::ToString<udp>(client_ep_ ? *client_ep_ : expected_client_ep_),
          ex.what());
      co_return Stop();
    }
  }

 private:
  VoidAwait RelayDataFromClient(
      const UdpRelayDataFromClientProcessorCb& data_processor) {
    utils::StaticBuffer<kDatagramMaxLen> buf;
    SentRelayData sent_data;
    for (;;) {
      buf.Clear();
      sent_data.Clear();
      const auto [err, datagram] = co_await RecvClientDatagram(buf);
      if (err) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, proxy_));
        co_return Stop();
      }
      if (!datagram) {
        continue;
      }
      const auto target_server =
          co_await FindOrMakeTargetServer(datagram->header.addr);
      if (!target_server) {
        co_return Stop();
      }
      auto& target_server_data = target_server->second.get();
      data_processor(
          reinterpret_cast<const char*>(datagram->data.data),
          datagram->data.data_size, target_server_data.ep,
          [&](const char* data, size_t size) { sent_data.Send(data, size); });
      if (!co_await sent_data.ForEach(
              [&](const RelayData& relay_data) noexcept -> BoolAwait {
                co_return co_await SendToNet(target_server_data.connect,
                                             target_server_data.ep, relay_data);
              })) {
        co_return Stop();
      }
    }
  }

  VoidAwait ProcessTargetServer(TargetServer target_server) noexcept {
    try {
      const auto data_processor = udp_relay_data_processor_.server_to_client(
          *client_ep_, target_server.second.get().ep);
      co_await RelayDataFromServer(target_server, data_processor);
    } catch (const std::exception& ex) {
      SOCKS5_LOG(
          debug,
          "Udp relay exception. Proxy: {}. Client: {}, Target server: {}. {}",
          net::ToString(proxy_), net::ToString<udp>(*client_ep_),
          net::ToString<udp>(target_server.second.get().ep), ex.what());
      co_return Stop();
    }
  }

  VoidAwait RelayDataFromServer(const TargetServer& target_server,
                                const UdpRelayDataProcessorCb& data_processor) {
    utils::StaticBuffer<kDatagramMaxLen> buf;
    SentRelayData sent_data;
    auto& target_server_data = target_server.second.get();
    for (;;) {
      buf.Clear();
      sent_data.Clear();
      watchdog_.Update();
      const auto [err, sender_ep] =
          co_await target_server_data.connect.Read(buf);
      if (err) {
        SOCKS5_LOG(debug, net::MakeErrorMsg(*err, target_server_data.connect));
        proxy_.Cancel();
        co_return;
      }
      if (target_server_data.ep != *sender_ep) {
        continue;
      }
      data_processor(
          buf.BeginRead(), buf.ReadableBytes(),
          [&](const char* data, size_t size) { sent_data.Send(data, size); });
      if (!co_await sent_data.ForEach(
              [&](const RelayData& relay_data) noexcept -> BoolAwait {
                co_return co_await SendToNet(target_server_data, relay_data);
              })) {
        co_return Stop();
      }
    }
  }

  void RunTargetServerHandler(const asio::any_io_executor& executor,
                              TargetServer target_server) {
    asio::co_spawn(
        executor,
        [self = this->shared_from_this(), target_server, this] {
          return ProcessTargetServer(std::move(target_server));
        },
        asio::detached);
  }

  BoolAwait SendToNet(net::UdpConnection& connect, const udp::endpoint& ep,
                      const RelayData& relay_data) noexcept {
    watchdog_.Update();
    if (const auto err = co_await connect.Send(
            ep, reinterpret_cast<const char*>(relay_data.first),
            relay_data.second)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, connect));
      co_return false;
    }
    co_return true;
  }

  BoolAwait SendToNet(TargetServerData& target_server,
                      const RelayData& relay_data) noexcept {
    const auto buffs =
        common::MakeDatagramBuffs(utils::MakeBuffer(target_server.addr),
                                  relay_data.first, relay_data.second);
    watchdog_.Update();
    if (const auto err = co_await proxy_.Send(*client_ep_, buffs)) {
      SOCKS5_LOG(debug, net::MakeErrorMsg(*err, proxy_));
      co_return false;
    }
    co_return true;
  }

  const UdpRelayDataProcessor& udp_relay_data_processor_;
};

template <typename T, typename... Args>
VoidAwait RunRelayHandler(net::TcpConnection client, net::UdpConnection proxy,
                          const proto::Addr& client_addr, const Config& config,
                          Args&&... args) {
  SOCKS5_LOG(debug,
             "Udp relay started. Client tcp socket: {}. Proxy udp socket: {}. "
             "Expected client udp addr: {}",
             net::ToString(client), net::ToString(proxy),
             common::ToString(client_addr));
  std::shared_ptr<T> handler;
  try {
    utils::Watchdog watchdog{co_await asio::this_coro::executor,
                             config.udp_relay_timeout};
    handler =
        std::make_shared<T>(std::move(client), std::move(proxy), client_addr,
                            watchdog, config, std::forward<Args>(args)...);
    co_await (handler->ProcessUdp() || handler->ProcessTcp() || watchdog.Run());
    SOCKS5_LOG(debug,
               "Udp relay finished. Proxy udp socket: {}. "
               "Client udp addr: {}",
               handler->ProxyAddrStr(), handler->ClientAddrStr());
  } catch (const std::exception&) {
    SOCKS5_LOG(debug,
               "Udp relay finished. Proxy udp socket: {}. "
               "Client udp addr: {}",
               handler->ProxyAddrStr(), handler->ClientAddrStr());
    throw;
  }
}

}  // namespace

VoidAwait DefaultUdpRelayHandler(net::TcpConnection client,
                                 net::UdpConnection proxy,
                                 proto::Addr client_addr, const Config& config,
                                 common::Metrics& metrics) {
  co_await RunRelayHandler<Handler>(std::move(client), std::move(proxy),
                                    client_addr, config, metrics);
}

VoidAwait UdpRelayHandlerWithDataProcessor(
    net::TcpConnection client, net::UdpConnection proxy,
    proto::Addr client_addr, const Config& config, common::Metrics& metrics,
    const UdpRelayDataProcessor& data_processor) {
  co_await RunRelayHandler<HandlerWithDataProcessor>(
      std::move(client), std::move(proxy), client_addr, config, metrics,
      data_processor);
}

}  // namespace socks5::server