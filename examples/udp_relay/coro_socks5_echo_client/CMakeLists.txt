add_executable(udp_associate_cmd_coro_socsk5_echo_client main.cpp)

target_link_libraries(udp_associate_cmd_coro_socsk5_echo_client 
  Boost::boost 
  socks5
)