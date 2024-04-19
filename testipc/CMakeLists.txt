include_directories(
    ./
    )

FILE(GLOB TESTIPC_LIST
    "../*.h"
    "*.cpp" "*.h"
)
link_libraries(monipc)
add_executable(ipctest ${TESTIPC_LIST})
set_target_properties(ipctest PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -D_GNU_SOURCE")
