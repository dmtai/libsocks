add_executable(connect_cmd_socks5_proxy main.cpp)

target_link_libraries(connect_cmd_socks5_proxy 
  PRIVATE 
    Boost::boost
    socks5
)