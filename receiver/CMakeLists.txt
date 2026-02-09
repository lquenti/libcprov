cmake_minimum_required(VERSION 3.16)
project(libcprov_receiver)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(libcprov_receiver
    src/main.cpp
    src/logserver.cpp
    src/db.cpp
    src/db_access.cpp
    src/parser.cpp
    src/json_string_builders.cpp
    src/sqlite3.c
)

target_include_directories(libcprov_receiver PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/config
)

target_link_libraries(libcprov_receiver PRIVATE
    simdjson::simdjson
    config_parser
)
