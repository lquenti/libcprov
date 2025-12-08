cmake_minimum_required(VERSION 3.16)
project(libcprov_receiver)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(SQLite3 REQUIRED)

find_library(SIMDJSON_LIB simdjson REQUIRED)

include(FetchContent)

FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.27.0
)

FetchContent_MakeAvailable(httplib)

add_executable(libcprov_receiver
    src/main.cpp
    src/logserver.cpp
    src/db.cpp
)

target_include_directories(libcprov_receiver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(libcprov_receiver PRIVATE ${SIMDJSON_LIB} SQLite::SQLite3)

target_include_directories(libcprov_receiver PRIVATE include ${httplib_SOURCE_DIR})
