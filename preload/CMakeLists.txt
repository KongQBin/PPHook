include_directories(
    ./
    )

FILE(GLOB PRELOAD_LIST
    "../*.h"
    "*.c" "*.h"
)

link_libraries(
    dl
    rt
)
add_library(nhook SHARED ${PRELOAD_LIST})
set_target_properties(nhook PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE -fvisibility=hidden")

# 删除hook
# sudo sed -i '/nhook/d' /etc/ld.so.preload
# 添加hook
# echo "/etc/libnhook.so" | sudo tee -a  /etc/ld.so.preload > /dev/null
