add_executable(connect_cmd_coro_socks5_echo_client main.cpp)

target_link_libraries(connect_cmd_coro_socks5_echo_client 
  Boost::boost 
  socks5
)