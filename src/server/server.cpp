#include <socks5/server/server.hpp>
#include <utils/thread_pool.hpp>
#include <utils/logger.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <server/listener.hpp>
#include <mutex>

namespace socks5::server {

struct Server::Impl {
  IoContextPtr io_context;
  std::any tcp_relay_handler;
  std::any udp_relay_handler;
  detail::ListenerRunner listener_runner;
  ConfigPtr config;
  common::MetricsPtr metrics;
  auth::server::UserAuthCbPtr user_auth_cb;
  TcpRelayDataProcessorPtr tcp_relay_data_processor;
  UdpRelayDataProcessorPtr udp_relay_data_processor;
  utils::ThreadPool thread_pool;
  std::mutex mtx;
};

Server::Server(IoContextPtr io_context, std::any tcp_relay_handler,
               std::any udp_relay_handler,
               detail::ListenerRunner listener_runner, ConfigPtr config_ptr,
               common::MetricsPtr metrics,
               auth::server::UserAuthCbPtr user_auth_cb,
               TcpRelayDataProcessorPtr tcp_data_processor,
               UdpRelayDataProcessorPtr udp_data_processor)
    : impl_{std::move(io_context),
            std::move(tcp_relay_handler),
            std::move(udp_relay_handler),
            std::move(listener_runner),
            std::move(config_ptr),
            std::move(metrics),
            std::move(user_auth_cb),
            std::move(tcp_data_processor),
            std::move(udp_data_processor),
            utils::ThreadPool{config_ptr->threads_num}} {};

Server::~Server() {
  try {
    Wait();
  } catch (const std::exception& ex) {
    SOCKS5_LOG(error, "Server exception. msg={}", ex.what());
  }
}

void Server::Run() {
  std::lock_guard lk{impl_->mtx};
  impl_->thread_pool.JoinAll();
  SOCKS5_LOG(info, "Socks5 server started");
  ResetComponents();
  RunListener();
  const auto thread_cb = [this] {
    while (!impl_->io_context->stopped()) {
      try {
        impl_->io_context->run();
      } catch (const std::exception& ex) {
        SOCKS5_LOG(error, "Unhandled exception: {}", ex.what());
      } catch (...) {
        SOCKS5_LOG(error, "Unknown exception: {}",
                   boost::current_exception_diagnostic_information());
      }
    }
  };
  impl_->thread_pool.Run(std::move(thread_cb));
};

void Server::Wait() {
  std::lock_guard lk{impl_->mtx};
  impl_->thread_pool.JoinAll();
}

size_t Server::GetRecvBytesTotal() const noexcept {
  return impl_->metrics->GetRecvBytesTotal();
}

size_t Server::GetSentBytesTotal() const noexcept {
  return impl_->metrics->GetSentBytesTotal();
}

void Server::Stop() noexcept {
  impl_->io_context->stop();
  SOCKS5_LOG(info, "Socks5 server stopped");
}

bool Server::Stopped() noexcept { return impl_->io_context->stopped(); }

void Server::RunListener() const { impl_->listener_runner(); }

void Server::ResetComponents() {
  impl_->io_context->restart();
  impl_->metrics->Clear();
}

asio::io_context& Server::IOContext() noexcept { return *impl_->io_context; }

const asio::io_context& Server::IOContext() const noexcept {
  return *impl_->io_context;
}

}  // namespace socks5::server