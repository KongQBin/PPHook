project(PLHOOK)
cmake_minimum_required(VERSION 2.8.12)
include_directories(
    ./
    )
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_BUILD_TYPE "Debug")
add_subdirectory(preload)
add_subdirectory(monipc)
add_subdirectory(testipc)
add_subdirectory(testdm)


