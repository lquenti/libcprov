cmake_minimum_required(VERSION 3.16)
project(libcprov_visualizer)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(CURL REQUIRED)

find_library(SIMDJSON_LIB simdjson REQUIRED)

add_executable(libcprov_visualizer
    src/main.cpp
    src/parser.cpp
)

target_include_directories(libcprov_visualizer PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(libcprov_visualizer PRIVATE
    CURL::libcurl
    ${SIMDJSON_LIB}
)
