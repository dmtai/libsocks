add_executable(udp_associate_cmd_echo_server main.cpp)

target_link_libraries(udp_associate_cmd_echo_server 
  Boost::boost 
  fmt::fmt
)