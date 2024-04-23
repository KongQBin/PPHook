#include <sys/types.h>
#include "define.h"
#include "ipclient.h"

char *GLIBC_VERSION[] =
{
        "GLIBC_2.2.5",
        "GLIBC_2.17",
};
// 查询并初始化真实函数地址
__attribute ((constructor)) void plInit(void)
{
    do
    {
        for(int i=0;i<sizeof(GLIBC_VERSION)/sizeof(GLIBC_VERSION[0]);++i)
        {
            real_dlsym = (fc_dlsym)dlvsym(REAL_LIBC, "dlsym", GLIBC_VERSION[i]);
            if(real_dlsym)  break;
        }
        // 文件监控及保护
        INIT_PTR(long,open,(const char *,int,mode_t));
        INIT_PTR(long,open64,(const char *,int,mode_t));
        INIT_PTR(long,openat,(int __fd, const char *__file, int __oflag, .../*mode_t*/));
        INIT_PTR(long,close,(int));
        INIT_PTR(long,rename,(const char *__old, const char *__new));
        INIT_PTR(long,renameat,(int __oldfd, const char *__old, int __newfd,const char *__new));
        INIT_PTR(long,renameat2,(int __oldfd, const char *__old, int __newfd,const char *__new, unsigned int __flags));
        INIT_PTR(long,unlink,(const char *__name));
        INIT_PTR(long,unlinkat,(int __fd, const char *__name, int __flag));
        // 进程防护
        INIT_PTR(long,execve,(const char *__path, char *const __argv[], char *const __envp[]));
        INIT_PTR(long,execveat,(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags));
        INIT_PTR(long,fexecve,(int __fd, char *const __argv[], char *const __envp[]));
        // 驱动防护
        INIT_PTR(long,finit_module,(int fd, const char *param_values,int flags));
        INIT_PTR(long,init_module,(const void *module_image, unsigned long len, const char *param_values, const struct module *mod));
        INIT_PTR(long,delete_module,(const char *name_user, unsigned int flags));
        // syscall 比较特殊，获取不到地址或者拿获取到的地址进行调用会段错误
        // 它是由LIBC进行特殊处理的
        INIT_PTR(long, syscall,(long int __sysno, ...));

    }while(0);
    // 打开日志
    if(real_open64)
        gLogFd = real_open64("/tmp/plog",O_CREAT|O_WRONLY|O_APPEND,0777);
    else
        gLogFd = real_open("/tmp/plog",O_CREAT|O_WRONLY|O_APPEND,0777);
    if(gLogFd >=0)
        chmod("/tmp/plog",0777);
    // 初始化ipc通信
    initIpc();
}
// 反初始化
__attribute ((destructor)) void plFini(void)
{
    if(gLogFd >= 0) real_close(gLogFd);
    unInitIpc();
}
