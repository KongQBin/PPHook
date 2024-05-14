#include "setwhite.h"
#include "define.h"

// 作为陷阱使用，当其被赋值时，
// 可以作出相应的反映，比如可以调用exit()直接结束调用者
// 可以仿照setPreloadIsWhite_101定义多个陷阱以迷惑恶意程序
int trap = 0;
int white = 0;  // 真正的白名单标识
NHOOK_EXPORT void setPreloadIsWhite_100(int onoff)
{
    white = onoff;
}
asm(".symver setPreloadIsWhite_100, setPreloadIsWhite@CX_PRELOAD_1.0.0");

NHOOK_EXPORT void setPreloadIsWhite_101(int onoff)
{
    trap = onoff;
}
asm(".symver setPreloadIsWhite_101, setPreloadIsWhite@@CX_PRELOAD_1.0.1");
