add_executable(connect_cmd_socks5_proxy_with_data_processor main.cpp)

target_link_libraries(connect_cmd_socks5_proxy_with_data_processor 
  PRIVATE 
    Boost::boost
    socks5
)