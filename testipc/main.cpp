#include "taskopt.h"
#include <unistd.h>
#include <dlfcn.h>

typedef void (*SetWhiteType)(int);
SetWhiteType setWhite;
int main(int argc, char **argv)
{
    //RTLD_NEXT
    setWhite = (SetWhiteType)dlvsym(RTLD_NEXT, "setPreloadIsWhite", "CX_PRELOAD_1.0.0");
    if(setWhite) setWhite(1);
    else
    {
        printf("symbol setWhite is not found\n");
        return 0;
    }

    TaskOpt taskOpt;
    taskOpt.init();
    while(1) sleep(1);
    return 0;
}
