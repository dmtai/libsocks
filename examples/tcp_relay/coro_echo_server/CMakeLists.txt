add_executable(connect_cmd_coro_echo_server main.cpp)

target_link_libraries(connect_cmd_coro_echo_server 
  Boost::boost 
  fmt::fmt
)