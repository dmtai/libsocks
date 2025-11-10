#pragma once

#include <boost/asio.hpp>
#ifdef __cpp_impl_coroutine
#include <boost/asio/experimental/awaitable_operators.hpp>
#endif
#include <socks5/utils/status.hpp>

namespace socks5 {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

using IoContextPtr = std::shared_ptr<asio::io_context>;
using SocketOpt = std::optional<tcp::socket>;
using UdpSocketRef = std::reference_wrapper<udp::socket>;

template <typename T>
using EndpointOpt = std::optional<typename T::endpoint>;

using TcpEndpointOpt = EndpointOpt<tcp>;
using UdpEndpointOpt = EndpointOpt<udp>;
using EndpointConstRef = std::reference_wrapper<const udp::endpoint>;

template <typename T>
using EndpointsOpt = std::optional<asio::ip::basic_resolver_results<T>>;
template <typename T>
using EndpointsOrError = utils::ErrorOr<EndpointsOpt<T>>;

template <typename T>
using EndpointOrError = utils::ErrorOr<EndpointOpt<T>>;
template <typename T>
using EndpointOrErrorOpt = std::optional<EndpointOrError<T>>;

using TcpEndpointOrError = EndpointOrError<tcp>;
using TcpEndpointOrErrorOpt = EndpointOrErrorOpt<tcp>;

using UdpEndpointOrError = EndpointOrError<udp>;
using UdpEndpointOrErrorOpt = EndpointOrErrorOpt<udp>;

using BytesCountOrError = utils::ErrorOr<size_t>;
using BytesCountOrErrorAwait = asio::awaitable<BytesCountOrError>;

using CancellationSlot = boost::asio::cancellation_slot;
using CancellationSlotOpt = std::optional<CancellationSlot>;

#ifdef __cpp_impl_coroutine

constexpr auto use_nothrow_awaitable = asio::as_tuple(asio::use_awaitable);
using namespace asio::experimental::awaitable_operators;

template <typename T>
using EndpointOptAwait = asio::awaitable<EndpointOpt<T>>;

using UdpEndpointOptAwait = asio::awaitable<UdpEndpointOpt>;

template <typename T>
using EndpointsOrErrorAwait = asio::awaitable<EndpointsOrError<T>>;

template <typename T>
using EndpointOrErrorAwait = asio::awaitable<EndpointOrError<T>>;

using TcpEndpointOrErrorAwait = EndpointOrErrorAwait<tcp>;

using UdpEndpointOrErrorAwait = EndpointOrErrorAwait<udp>;

using BoolAwait = asio::awaitable<bool>;
using VoidAwait = asio::awaitable<void>;
using ErrorAwait = asio::awaitable<boost::system::error_code>;

#endif

}  // namespace socks5