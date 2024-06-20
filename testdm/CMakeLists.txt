include_directories(
    ./
    )

FILE(GLOB TESTDM_LIST
    "*.cpp"
)
set(CMAKE_CXX_COMPILER "g++")
add_executable(dm ${TESTDM_LIST})
set_target_properties(dm PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -D_GNU_SOURCE -lpthread -Wl,--no-as-needed")
