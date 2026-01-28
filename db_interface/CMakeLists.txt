cmake_minimum_required(VERSION 3.16)
project(db_interface LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SIMDJSON REQUIRED simdjson)

set(PROJECT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(db_interface
    src/querier.cpp
    #src/parser.cpp
    src/build_json.cpp
)

target_include_directories(db_interface PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_INCLUDE_DIR}
    ${SIMDJSON_INCLUDE_DIRS}
    /usr/include
)

target_link_libraries(db_interface PRIVATE
    CURL::libcurl
    ${SIMDJSON_LIBRARIES}
)
