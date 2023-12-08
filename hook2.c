#include "hook2.h"

FILE *debugfp = NULL;
#define mprintf(fmt,...) \
{\
    if(!debugfp) debugfp = fopen("/tmp/zyhook.log","a+");\
    if( debugfp) fprintf(debugfp,fmt,##__VA_ARGS__);\
}

// 反初始化函数
__attribute__((destructor))
void on_hook2_unload(void)
{
    printf("lib hook 2 unload\n");
    if(debugfp) {fclose(debugfp);debugfp = NULL;};
}

char *mhooknames[] = {
    "close",
    "dlsym",
};

int inited = 0;
char **names = NULL;
void **funcs = NULL;
int len = 0;
static inline void *getfuncptr(const char* name)
{
    printf("getfuncptr --->\n");
    if(!inited)
    {
        gethooks(&names,&funcs,&len);
        inited = 1;
    }

    for(int i = 0; i < len; ++i)
    {
        if(!strncmp(mhooknames[i],name,strlen(name)))
            return funcs[i];
    }
    return NULL;
}

//int unlink(const char *path)
//{
//    mprintf("unlink %s\n",path);
//    int(*munlink)(const char*) = getfuncptr("unlink");
//    if(munlink)
//        return munlink(path);
//    else
//        return -1;
//}

int(*sys_close)(int) = NULL;
int close(int fd)
{
    if(!sys_close) sys_close = getfuncptr("close");
    mprintf("mclose is %x sys_close is %x fd is %d\n",close,sys_close,fd);
    if(sys_close)
        return sys_close(fd);
    else
    {
        mprintf("sys_close is null\n");
        return -1;
    }
}

void *(*sys_dlsym)(void *,const char*) = NULL;
void *dlsym(void *handle,const char*symbol)
{
    mprintf("mdlsym is %x sys_dlsym is %x symbol is %d\n",dlsym,sys_dlsym,symbol);
    if(!sys_dlsym) sys_dlsym = getfuncptr("dlsym");
    if(strcmp(symbol,"close"))
        return sys_dlsym(handle,symbol);
    else
        return close;
}
