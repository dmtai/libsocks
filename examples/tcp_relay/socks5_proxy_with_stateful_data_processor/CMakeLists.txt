add_executable(connect_cmd_socks5_proxy_with_stateful_data_processor main.cpp)
target_include_directories(connect_cmd_socks5_proxy_with_stateful_data_processor 
  PRIVATE 
    Boost::Boost 
    ${CMAKE_SOURCE_DIR}/include/
)
target_link_libraries(connect_cmd_socks5_proxy_with_stateful_data_processor 
  PRIVATE 
    Boost::boost
    socks5
)