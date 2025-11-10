#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  auto proxy = builder.Build();
  proxy.Run();
  proxy.Wait();
  return 0;
}