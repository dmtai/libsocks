#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>

const std::string kListenerAddr{"127.0.0.1"};
constexpr unsigned short kListenerPort{1080};

constexpr std::string_view kExpectedUsername{"username1"};
constexpr std::string_view kExpectedPassword{"12345"};

int main() {
  auto builder =
      socks5::server::MakeServerBuilder(kListenerAddr, kListenerPort);
  builder.SetUserAuthCb([](std::string_view username, std::string_view pass,
                           const socks5::auth::server::Config& config) {
    return username == kExpectedUsername && pass == kExpectedPassword;
  });
  // or builder.SetAuthUsername(kExpectedUsername) and
  // builder.SetAuthPassword(kExpectedPassword);

  builder.EnableUserAuth(true);

  auto proxy = builder.Build();
  proxy.Run();
  proxy.Wait();
  return 0;
}