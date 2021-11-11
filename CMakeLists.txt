cmake_minimum_required(VERSION 3.5)
project(stacktrace)

set(CMAKE_CXX_STANDARD 14)

option(BUILD_STACKTRACE_EXAMPLES "Build examples" OFF)

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE include)
target_link_libraries(${PROJECT_NAME} INTERFACE -ldl)

if (BUILD_STACKTRACE_EXAMPLES)
    add_subdirectory(examples)
endif ()
