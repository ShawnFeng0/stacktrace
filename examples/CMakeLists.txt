project(stacktrace_example)

add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL examples.cc)
target_link_libraries(${PROJECT_NAME} PRIVATE stacktrace)
target_link_options(${PROJECT_NAME} PRIVATE -rdynamic)
