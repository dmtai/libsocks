add_executable(connect_cmd_async_socsk5_echo_client main.cpp)

target_link_libraries(connect_cmd_async_socsk5_echo_client 
  Boost::boost 
  socks5
)