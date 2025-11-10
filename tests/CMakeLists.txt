cmake_minimum_required(VERSION 3.20)
project(socks5_tests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)

find_package(GTest REQUIRED)

file(GLOB_RECURSE SOURCES
  ${CMAKE_SOURCE_DIR}/tests/*.cpp
  ${CMAKE_SOURCE_DIR}/tests/*.hpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} 
  PRIVATE 
    fmt::fmt
    Boost::boost
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(${PROJECT_NAME} 
  PRIVATE 
    fmt::fmt
    Boost::boost
    spdlog::spdlog
    socks5
    GTest::gtest
    GTest::gtest_main
)
if(NOT WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()

add_test(NAME ${PROJECT_NAME} 
         COMMAND ${CMAKE_BINARY_DIR}/tests/${PROJECT_NAME})