add_executable(bind_cmd_coro_socsk5_echo_client main.cpp)

target_link_libraries(bind_cmd_coro_socsk5_echo_client 
  PRIVATE 
    fmt::fmt
    Boost::boost
    socks5
)