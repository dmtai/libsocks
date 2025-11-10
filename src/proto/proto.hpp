#pragma once

#include <array>
#include <cstdint>

namespace socks5::proto {

/**
 * @brief Socks protocol version.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 */
enum Version : uint8_t {
  kVersionVer5 = 0x05,
};

/**
 * @brief Socks5 auth method id.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 */
enum AuthMethod : uint8_t {
  kAuthMethodNone = 0x00,
  kAuthMethodGSSAPI = 0x01,
  kAuthMethodUser = 0x02,
  kAuthMethodChallengeHandshakeAuth = 0x03,
  kAuthMethodUnassigned = 0x04,
  kAuthMethodChallengeResponseAuth = 0x05,
  kAuthMethodSSL = 0x06,
  kAuthMethodNDSAuth = 0x07,
  kAuthMethodMultiAuth = 0x08,
  kAuthMethodJsonParamBlock = 0x09,
  kAuthMethodMethodDeny = 0xFF,
};

/**
 * @brief Socks command id.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-4
 *
 */
enum RequestCmd : uint8_t {
  kRequestCmdConnect = 0x01,
  kRequestCmdBind = 0x02,
  kRequestCmdUdpAssociate = 0x03,
};

/**
 * @brief Socks proxy reply status to request.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-6
 *
 */
enum ReplyRep : uint8_t {
  kReplyRepSuccess = 0x00,
  kReplyRepFail = 0x01,
  kReplyRepNotAllowed = 0x02,
  kReplyRepNetworkUnreachable = 0x03,
  kReplyRepHostUnreachable = 0x04,
  kReplyRepConnectionRefused = 0x05,
  kReplyRepTTLExpired = 0x06,
  kReplyRepCommandNotSupported = 0x07,
  kReplyRepAddrTypeNotSupported = 0x08,
};

/**
 * @brief Address type. https://datatracker.ietf.org/doc/html/rfc1928#section-5
 *
 */
enum AddrType : uint8_t {
  kAddrTypeIPv4 = 0x01,
  kAddrTypeDomainName = 0x03,
  kAddrTypeIPv6 = 0x04,
};

/**
 * @brief Udp fragmentation status. Fragmentation isn't currently supported.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-7
 *
 */
enum UdpFrag : uint8_t {
  kUdpFragNoFrag = 0x00,
};

/**
 * @brief Username/Password authentication version.
 * https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 */
enum UserAuthVersion : uint8_t {
  kUserAuthVersionVer = 0x01,
};

/**
 * @brief Username/Password authentication proxy server status.
 * https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 */
enum UserAuthStatus : uint8_t {
  kUserAuthStatusSuccess = 0x00,
  kUserAuthStatusFailure = 0x01,
};

/**
 * @brief IPv4 address data.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-5
 *
 */
struct IPv4 final {
  std::array<uint8_t, 4> addr;
  uint16_t port;
};

/**
 * @brief IPv6 address data.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-5
 *
 */
struct IPv6 final {
  std::array<uint8_t, 16> addr;
  uint16_t port;
};

/**
 * @brief Domain address data.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-5
 *
 */
struct Domain final {
  uint8_t length;
  std::array<uint8_t, 256> addr;
  uint16_t port;
};

/**
 * @brief IPv4/IPv6/domain address data.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-5
 *
 */
struct Addr final {
  uint8_t atyp;
  union {
    IPv4 ipv4;
    IPv6 ipv6;
    Domain domain;
  } addr;
};

/**
 * @brief The first message a client sends to a proxy server to establish a
 * connection. Contains authentication methods supported by the client.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 */
struct ClientGreeting final {
  uint8_t ver;
  uint8_t nmethods;
  std::array<uint8_t, 256> methods;
};

/**
 * @brief Socks proxy server reply to client request.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-6
 *
 */
struct Reply final {
  uint8_t ver;
  uint8_t rep;
  uint8_t rsv;
  Addr bnd_addr;
};

/**
 * @brief Client request to socks proxy server.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-4
 *
 */
struct Request final {
  uint8_t ver;
  uint8_t cmd;
  uint8_t rsv;
  Addr dst_addr;
};

/**
 * @brief The proxy server's first response to a client request with
 * ClientGreeting. Contains the authentication method selected by the proxy
 * server from those sent in the client's ClientGreeting request.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 */
struct ServerChoice final {
  uint8_t ver;
  uint8_t method;
};

/**
 * @brief Socks5 udp datagram header.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-7
 *
 */
struct DatagramHeader final {
  uint16_t rsv;
  uint8_t frag;
  Addr addr;
};

/**
 * @brief Socks5 udp datagram data.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-7
 *
 */
struct DatagramData final {
  uint8_t* data;
  uint16_t data_size;
};

/**
 * @brief Socks5 udp datagram.
 * https://datatracker.ietf.org/doc/html/rfc1928#section-7
 *
 */
struct Datagram final {
  DatagramHeader header;
  DatagramData data;
};

/**
 * @brief Client request for Username/Password authentication(rfc 1929).
 * https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 */
struct UserAuthRequest final {
  uint8_t ver;
  uint8_t ulen;
  std::array<uint8_t, 256> uname;
  uint8_t plen;
  std::array<uint8_t, 256> passwd;
};

/**
 * @brief Proxy server response for Username/Password authentication(rfc 1929).
 * https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 */
struct UserAuthResponse final {
  uint8_t ver;
  uint8_t status;
};

}  // namespace socks5::proto