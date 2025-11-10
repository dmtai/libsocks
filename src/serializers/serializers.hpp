#pragma once

#include <proto/proto.hpp>
#include <common/defs.hpp>

namespace socks5::serializers {

ServerChoiceBuf Serialize(const proto::ServerChoice& server_choice) noexcept;
ReplyBuf Serialize(const proto::Reply& reply) noexcept;
UserAuthResponseBuf Serialize(
    const proto::UserAuthResponse& user_auth_resp) noexcept;
ClientGreetingBuf Serialize(
    const proto::ClientGreeting& client_greeting) noexcept;
RequestBuf Serialize(const proto::Request& request) noexcept;
UserAuthRequestBuf Serialize(const proto::UserAuthRequest& request) noexcept;
DatagramHeaderBuf Serialize(const proto::DatagramHeader& header) noexcept;
AddrBuf Serialize(const proto::Addr& addr) noexcept;

}  // namespace socks5::serializers