#include "hook1.h"


#define HOOK_LEN    2
// func name 列表
char **hooknames = NULL;
// func ptr 列表
void **hookfuncs = NULL;
void *handle;
// 获取 hook 列表
void gethooks(char ***names, void ***funcs, int *len)
{
//    printf("hooknames = %x, hookfuncs = %x\n",hooknames,hookfuncs);
    *names = hooknames;
    *funcs = hookfuncs;
    *len = sizeof(hooknames)/sizeof(hooknames[0]);

    printf("close is %x\n",hookfuncs[0]);
    printf("dlsym is %x\n",hookfuncs[1]);
    for(int i=0;i<*len;++i)
        printf("i = %d, name = %s, funcs = %x\n", i, hooknames[i], hookfuncs[i]);
}

// 初始化函数
__attribute__((constructor))
void on_load(void)
{
    printf("lib 1 load\n");
    // 先保存符号
    hooknames = NULL;
    hookfuncs = NULL;
    hooknames = calloc(1,sizeof(char*)*HOOK_LEN);
    hookfuncs = calloc(1,sizeof(char*)*HOOK_LEN);
    if(hooknames && hookfuncs)
    {
        for(int i=0;i<HOOK_LEN;++i)
        {
            if(i == 0)
            {
                hooknames[i] = calloc(1,strlen("close") + 1);
                strcat(hooknames[i],"close");
                hookfuncs[i] = close;
            }
            else
            {
                hooknames[i] = calloc(1,strlen("dlsym") + 1);
                strcat(hooknames[i],"dlsym");
                hookfuncs[i] = dlsym;
            }
        }
    }
    // 然后手动打开hook并选择立即解析符号
    handle = dlopen("/home/user/MyGit/PPHook/build/libhook2.so",RTLD_NOW|RTLD_GLOBAL);
    if(!handle)
    {
        printf("dlopen error #%d : %s",errno,strerror(errno));
    }
//    if(hookfuncs) return;

}

// 反初始化函数
__attribute__((destructor))
void on_unload(void)
{
    printf("lib 1 unload\n");
    if(handle)  dlclose(handle);
}
