#include "hook1.h"

#if defined(RTLD_NEXT)
#  define REAL_LIBC RTLD_NEXT
#else
#  define REAL_LIBC ((void *) -1L)
#endif
#define FN(ptr, name)ptr = dlsym(REAL_LIBC, name)

// func name 列表
char *hooknames[] = {
    "close",
    "dlsym",
};
// func ptr 列表
void **hookfuncs = NULL;
// 获取 hook 列表
void gethooks(char ***names, void ***funcs, int *len)
{
    printf("hooknames = %x, hookfuncs = %x\n",hooknames,hookfuncs);
    *names = hooknames;
    *funcs = hookfuncs;
    *len = sizeof(hooknames)/sizeof(hooknames[0]);

    for(int i=0;i<*len;++i)
        printf("i = %d, name = %s, funcs = %x\n", i, hooknames[i], hookfuncs[i]);
}

// 初始化函数
__attribute__((constructor))
void on_load(void)
{
    printf("lib load\n");
    hookfuncs = calloc(1,sizeof(hooknames)/sizeof(hooknames[0])*sizeof(void*));
    if(!hookfuncs)  printf("lib load err\n");
    for(int i = 0; i < sizeof(hooknames)/sizeof(hooknames[0]);++i)
    {
        FN(hookfuncs[i],hooknames[i]);
        if(!hookfuncs[i]) printf("hook init %s error\n",hooknames[i]);
    }
}

// 反初始化函数
__attribute__((destructor))
void on_unload(void)
{
    printf("lib unload\n");
    if(hookfuncs) free(hookfuncs);
}
