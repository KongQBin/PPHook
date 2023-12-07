project(ProloadHook)
cmake_minimum_required(VERSION 3.5)
set(CMAKE_C_FLAGS "-std=gnu99")
add_library(hook1 SHARED hook1.c)

link_libraries(hook1)
add_library(hook2 SHARED hook2.c)
add_dependencies(hook2 hook1)

link_libraries(hook1)
add_executable(test main.c)
add_dependencies(test hook1)
