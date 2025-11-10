add_executable(connect_cmd_socks5_proxy_with_auth main.cpp)

target_link_libraries(connect_cmd_socks5_proxy_with_auth 
  PRIVATE 
    Boost::boost
    socks5
)