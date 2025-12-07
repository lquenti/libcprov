cmake_minimum_required(VERSION 3.16)
project(libcprov)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SIMDJSON REQUIRED simdjson)

set(PROJECT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
# -------- Prov Executable --------
add_executable(prov
    src/prov.cpp
    src/event_recorder.cpp
    src/parser.cpp
    src/processor.cpp
)

target_include_directories(prov PRIVATE
    ${PROJECT_INCLUDE_DIR}
    ${SIMDJSON_INCLUDE_DIRS}
    /usr/include
  )

target_link_libraries(prov PRIVATE
    CURL::libcurl
    pthread
    dl
    ${SIMDJSON_LIBRARIES}
)

# -------- Injector Shared Library --------
add_library(injector SHARED
    src/injector.cpp
)

target_link_libraries(injector PRIVATE
    pthread
    dl
)
