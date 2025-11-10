add_executable(bind_cmd_socks5_proxy main.cpp)

target_link_libraries(bind_cmd_socks5_proxy 
  PRIVATE 
    Boost::boost
    socks5
)