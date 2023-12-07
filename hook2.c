#include "hook2.h"

FILE *debugfp = NULL;
#define mprintf(fmt,...) if(debugfp) fprintf(debugfp,fmt,##__VA_ARGS__);
// 初始化函数
__attribute__((constructor))
void on_load(void)
{
    debugfp = fopen("/tmp/zyhook.log","a+");
    if(!debugfp)    printf("debugfp init error #%d : %s\n",errno,strerror(errno));
}

// 反初始化函数
__attribute__((destructor))
void on_unload(void)
{
    if(debugfp) fclose(debugfp);
}


int inited = 0;
char **names = NULL;
void **funcs = NULL;
int len = 0;
static inline void *getfuncptr(const char* name)
{
    if(!inited) gethooks(&names,&funcs,&len);
    for(int i = 0; i < len; ++i)
    {
        if(!strncmp(names[i],name,strlen(name)))
            return funcs[i];
    }
    return NULL;
}

int unlink(const char *path)
{
    mprintf("unlink %s\n",path);
    int(*munlink)(const char*) = getfuncptr("unlink");
    if(munlink)
        return munlink(path);
    else
        return -1;
}

int close(int fd)
{
    mprintf("close %d\n",fd);
    int(*mclose)(int) = getfuncptr("close");
    if(mclose)
        return mclose(fd);
    else
        return -1;
}
