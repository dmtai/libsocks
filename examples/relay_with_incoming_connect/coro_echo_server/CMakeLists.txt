add_executable(bind_cmd_coro_echo_server main.cpp)

target_link_libraries(bind_cmd_coro_echo_server 
  Boost::boost 
  fmt::fmt
)