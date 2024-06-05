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
set_target_properties(nhook PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ver.lds")
# 删除hook
# sudo sed -i '/nhook/d' /etc/ld.so.preload
# 添加hook
# echo "/etc/libnhook.so" | sudo tee -a  /etc/ld.so.preload > /dev/null

# 安装流程
# 在安装前应该将系统中现有的系统防护软件的防护开关关闭
# 安装成功后，可以将系统中的防护软件打开，否则安装过程中系统会死机
# 原因是：系统中的某些防护机制会检测到有些进程准备加载一个陌生的库，
# 它会提示你“是否允许使用”这个库，当你选择允许使用时，该库才会允许被系统使用
# 但它如果提示你“是否允许使用”，那么它本身就得先加载你的Preload库，如此变成死循环

# 注意:安装时可以将本库直接放置在/etc目录或系统的lib目录，
# 因为有些分区在系统开机时不一定被挂载，如果没被挂载的话，
# 那么一些进程在开机时将找不到本hook库进而忽略，从而脱离管控

# 卸载流程
# 卸载时，首先将ld.so.preload文件中本库的路径删除
# 理论上是可以将本库直接从/etc/目录进行删除的且不会影响已经加载过本库的进程，因为已经在内存中了
# 稳妥起见，也可以将本库mv至/tmp目录下，让系统下次开机时自动清理，避免此次开机已经加载过这个库的进程出现问题

