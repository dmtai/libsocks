add_executable(connect_cmd_socks5_proxy_handler main.cpp)

target_link_libraries(connect_cmd_socks5_proxy_handler 
  PRIVATE 
    Boost::boost
    socks5
)