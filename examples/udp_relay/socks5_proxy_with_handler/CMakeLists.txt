add_executable(udp_asociate_cmd_socks5_proxy_with_handler main.cpp)

target_link_libraries(udp_asociate_cmd_socks5_proxy_with_handler
  PRIVATE
    Boost::boost
    socks5
)
