include_directories(
    ./
    )

FILE(GLOB MONIPC_LIST
    "../*.h"
    "*.cpp" "*.h"
)

set(CMAKE_CXX_COMPILER "g++")
add_library(monipc SHARED ${MONIPC_LIST})
set_target_properties(monipc PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -D_GNU_SOURCE")
