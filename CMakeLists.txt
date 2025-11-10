cmake_minimum_required(VERSION 3.20)
project(
	socks5
	VERSION 1.0.0 
  HOMEPAGE_URL "https://github.com/dmtai/libsocks"
	DESCRIPTION "Library for writing SOCKS5 servers and clients with full support for  \
               RFC 1928(IPv4/IPv6, TCP/UDP, CONNECT/BIND/UDP ASSOCIATE commands) \
               and RFC 1929(Username/Password Authentication for SOCKS5)"
	LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)

include(cmake/sanitizers.cmake)

find_package(Boost REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(Threads REQUIRED)

file(GLOB_RECURSE SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp
)

if(SOCKS5_BUILD_SHARED OR BUILD_SHARED_LIBS)
	add_library(${PROJECT_NAME} SHARED ${SOURCES})
else()
	add_library(${PROJECT_NAME} STATIC ${SOURCES})
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE SOCKS5_EXPORTS)
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN 1
)

target_include_directories(${PROJECT_NAME} 
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
)

target_include_directories(${PROJECT_NAME} 
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    Boost::Boost
)

target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    Boost::boost
    spdlog::spdlog
    fmt::fmt
    Threads::Threads
)
if(NOT WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()

if(SOCKS5_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(SOCKS5_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
