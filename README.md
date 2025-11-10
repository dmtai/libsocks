# libsocks
[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Cross-platform library for writing **SOCKS5** servers and clients with full support for
[RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)(IPv4/IPv6, TCP/UDP, CONNECT/BIND/UDP ASSOCIATE commands) 
and [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929)
(username/password authentication for SOCKS5). The proxy server supports registering callbacks to process all relayed TCP and UDP traffic. 
The library is based on [Boost.Asio](https://github.com/boostorg/asio).


## Usage samples

SOCKS5 proxy server.

```cpp
#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>

int main() {
  auto builder =
      socks5::server::MakeServerBuilder("127.0.0.1", 1080);
  auto proxy = builder.Build();
  proxy.Run();
  proxy.Wait();
  return 0;
}
```

SOCKS5 client. Establish a TCP connection to the target server through a SOCKS5 proxy server.

```cpp
#include <boost/asio.hpp>
#include <socks5/client/client.hpp>
#include <socks5/auth/client/auth_options.hpp>
#include <socks5/common/address.hpp>
#include <iostream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::string_view kProxyServerIP{"127.0.0.1"};
constexpr unsigned short kProxyServerPort{1080};
constexpr std::string_view kTargetServerIP{"127.0.0.1"};
constexpr unsigned short kTargetServerPort{5555};
constexpr size_t kTimeout{5000};

asio::awaitable<void> Client() {
  tcp::endpoint proxy_server_ep{asio::ip::make_address_v4(kProxyServerIP),
                                kProxyServerPort};
  tcp::endpoint target_server_ep{asio::ip::make_address_v4(kTargetServerIP),
                                 kTargetServerPort};

  // Select an authentication method for the SOCKS5 proxy.
  auto auth_options = socks5::auth::client::MakeAuthOptions();
  auth_options.AddAuthMethod<socks5::auth::client::AuthMethod::kNone>();

  tcp::socket socket{co_await asio::this_coro::executor};
  // Connect asynchronously to the target server via the SOCKS5 proxy
  // using libsocks to relay TСP traffic. Overloads without coroutines
  // are also supported.
  const auto err = co_await socks5::client::AsyncConnect(
      socket, proxy_server_ep, socks5::common::Address{target_server_ep},
      auth_options, kTimeout);
  if (err) {
    std::cout << err.message() << std::endl;
    co_return;
  }
  // The connection to the target server via the SOCKS5 proxy has now been
  // established on the socket. You can send data to the target server through
  // the SOCKS5 proxy using this socket.
}

int main() {
  try {
    asio::io_context io_context{1};
    co_spawn(io_context, Client(), asio::detached);
    io_context.run();
  } catch (const std::exception& ex) {
    std::cerr << "Exception: " << ex.what() << std::endl;
    return 1;
  }
  return 0;
}
```
Also the proxy server supports registering [handlers](https://github.com/dmtai/test_socks5/blob/main/include/socks5/server/handler_defs.hpp)
and [data processors](https://github.com/dmtai/test_socks5/blob/main/include/socks5/server/relay_data_processor_defs.hpp) 
to process all relayed TCP and UDP traffic. Here's a simple data processor that process all relayed data, or see the 
[example](https://github.com/dmtai/test_socks5/blob/main/examples/tcp_relay/socks5_proxy_with_handler/main.cpp) of a TСP traffic handler.
Read more about [data processors and handlers](https://github.com/dmtai/test_socks5/blob/main/include/socks5/server/server_builder.hpp#L139).
```cpp
#include <boost/asio.hpp>
#include <socks5/server/server_builder.hpp>
#include <socks5/server/server.hpp>
#include <socks5/server/relay_data_processor_defs.hpp>
#include <socks5/server/handler_defs.hpp>
#include <iostream>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

int main() {
  auto builder =
      socks5::server::MakeServerBuilder("127.0.0.1", 1080);
  auto proxy_with_simple_data_processor = builder.Build(
      socks5::server::TcpRelayDataProcessor{
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return [&](const char* data, size_t size,
                       const socks5::server::RelayDataSender& send) {
              std::cout << "Client to server: " << std::string_view{data, size}
                        << std::endl;
              send(data, size);
            };
          },
          [&](const tcp::endpoint& from, const tcp::endpoint& to) {
            return [&](const char* data, size_t size,
                       const socks5::server::RelayDataSender& send) {
              std::cout << "Server to client: " << std::string_view{data, size}
                        << std::endl;
              send(data, size);
            };
          }},
      nullptr);
  proxy_with_simple_data_processor.Run();
  proxy_with_simple_data_processor.Wait();
  return 0;
}
```

## Examples
See more examples [here](https://github.com/dmtai/test_socks5/tree/main/examples).

## Documentation
All [exported logic](https://github.com/dmtai/test_socks5/tree/main/include) has built-in documentation and comments.

## Dependencies

- [Boost](https://github.com/boostorg/boost)
- [fmt](https://github.com/fmtlib/fmt)
- [spdlog](https://github.com/gabime/spdlog)

## Integration

Include to your project using cmake. Your project must also have [dependencies](https://github.com/dmtai/test_socks5/blob/main/conanfile.txt) available
(get them, for example, using [Conan](https://docs.conan.io/2/tutorial/consuming_packages/build_simple_cmake_project.html))
```cmake
add_subdirectory(third_party/libsocks) # path to the directory with libsocks
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    Boost::boost
    socks5
)
```

You can also build the library separately using Conan.
```
conan install . --output-folder=third_party_build --build=missing -s build_type=Release
 # the path to the toolchain may differ
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=third_party_build/build/generators/conan_toolchain.cmake -DSOCKS5_BUILD_EXAMPLES=ON
cmake --build build --config Release
```
For Visual Studio without cmake, build the library and set Additional Dependencies, Additional Library Directories, Additional Include Directories.
