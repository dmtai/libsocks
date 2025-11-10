add_executable(udp_asociate_cmd_socks5_proxy main.cpp)

target_link_libraries(udp_asociate_cmd_socks5_proxy 
  PRIVATE 
    Boost::boost
    socks5
)