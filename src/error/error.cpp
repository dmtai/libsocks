#include <socks5/error/error.hpp>
#include <proto/proto.hpp>

namespace socks5::error {

namespace {

class ErrorCategory : public boost::system::error_category {
 public:
  const char* name() const noexcept override;
  std::string message(int ev) const override;
};

const char* ErrorCategory::name() const noexcept { return "socks5_error"; }

std::string ErrorCategory::message(int ev) const {
  switch (static_cast<Error>(ev)) {
    case Error::kSucceeded: {
      return "Succeeded";
    }
    case Error::kGeneralFailure: {
      return "General SOCKS5 failure";
    }
    case Error::kConnectionNotAllowedByRuleset: {
      return "Connection not allowed by ruleset";
    }
    case Error::kNetworkUnreachable: {
      return "Network unreachable";
    }
    case Error::kHostUnreachable: {
      return "Host unreachable";
    }
    case Error::kConnectionRefused: {
      return "Connection refused";
    }
    case Error::kTtlExpired: {
      return "TTL expired";
    }
    case Error::kCommandNotSupported: {
      return "Command not supported";
    }
    case Error::kAddressTypeNotSupported: {
      return "Address type not supported";
    }
    case Error::kAuthFailure: {
      return "Authentication failure";
    }
    case Error::kTimeoutExpired: {
      return "Timeout expired";
    }
    case Error::kInvalidDatagram: {
      return "Invalid datagram";
    }
    case Error::kDomainResolutionFailure: {
      return "Domain resolution failure";
    }
    case Error::kCancellationFailure: {
      return "Cancellation failure";
    }
    case Error::kInvalidAddress: {
      return "Invalid address";
    }
  }
  return "Unrecognized error";
}

const ErrorCategory kErrorCategory{};

}  // namespace

boost::system::error_code make_error_code(Error err) noexcept {
  return {static_cast<int>(err), kErrorCategory};
}

boost::system::error_code MakeError(uint8_t reply_rep) noexcept {
  switch (reply_rep) {
    default: {
      return Error::kGeneralFailure;
    }
    case proto::ReplyRep::kReplyRepSuccess: {
      return Error::kSucceeded;
    }
    case proto::ReplyRep::kReplyRepFail: {
      return Error::kGeneralFailure;
    }
    case proto::ReplyRep::kReplyRepNotAllowed: {
      return Error::kConnectionNotAllowedByRuleset;
    }
    case proto::ReplyRep::kReplyRepNetworkUnreachable: {
      return Error::kNetworkUnreachable;
    }
    case proto::ReplyRep::kReplyRepHostUnreachable: {
      return Error::kHostUnreachable;
    }
    case proto::ReplyRep::kReplyRepConnectionRefused: {
      return Error::kConnectionRefused;
    }
    case proto::ReplyRep::kReplyRepTTLExpired: {
      return Error::kTtlExpired;
    }
    case proto::ReplyRep::kReplyRepCommandNotSupported: {
      return Error::kCommandNotSupported;
    }
    case proto::ReplyRep::kReplyRepAddrTypeNotSupported: {
      return Error::kAddressTypeNotSupported;
    }
  }
}

}  // namespace socks5::error