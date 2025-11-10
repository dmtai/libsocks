#pragma once

#include <optional>
#include <proto/proto.hpp>
#include <socks5/utils/buffer.hpp>
#include <socks5/common/asio.hpp>

namespace socks5 {

constexpr size_t kDatagramMaxLen{65507};

using AddrOpt = std::optional<proto::Addr>;
using AddrRef = std::reference_wrapper<proto::Addr>;
using AddrConstRef = std::reference_wrapper<const proto::Addr>;
using AddrBuf = utils::StaticBuffer<sizeof(proto::Addr)>;
using AddrBufOpt = std::optional<AddrBuf>;

using ClientGreetingOpt = std::optional<proto::ClientGreeting>;
using ClientGreetingOptAwait = asio::awaitable<ClientGreetingOpt>;
using ClientGreetingBuf = utils::StaticBuffer<sizeof(proto::ClientGreeting)>;

using ReplyOpt = std::optional<proto::Reply>;
using ReplyBuf = utils::StaticBuffer<sizeof(proto::Reply)>;
using ReplyBufOpt = std::optional<ReplyBuf>;

using RequestOpt = std::optional<proto::Request>;
using RequestOptAwait = asio::awaitable<RequestOpt>;
using RequestBuf = utils::StaticBuffer<sizeof(proto::Request)>;

using ReplyOpt = std::optional<proto::Reply>;
using ReplyOptAwait = asio::awaitable<ReplyOpt>;
using ReplyBuf = utils::StaticBuffer<sizeof(proto::Reply)>;

using ServerChoiceOpt = std::optional<proto::ServerChoice>;
using ServerChoiceBuf = utils::StaticBuffer<sizeof(proto::ServerChoice)>;

using DatagramHeaderBuf = utils::StaticBuffer<sizeof(proto::DatagramHeader)>;

using DatagramOpt = std::optional<proto::Datagram>;
using DatagramBuf = utils::StaticBuffer<kDatagramMaxLen>;
using DatagramBufOpt = std::optional<DatagramBuf>;

using UserAuthRequestOpt = std::optional<proto::UserAuthRequest>;
using UserAuthRequestBuf = utils::StaticBuffer<sizeof(proto::UserAuthRequest)>;
using UserAuthRequestOptAwait = asio::awaitable<UserAuthRequestOpt>;

using UserAuthResponseOpt = std::optional<proto::UserAuthResponse>;
using UserAuthResponseBuf =
    utils::StaticBuffer<sizeof(proto::UserAuthResponse)>;

}  // namespace socks5
