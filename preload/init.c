#include <sys/types.h>
#include "define.h"
#include "ipclient.h"


/* ！！！！！！！！！！慎用MUTEX！！！！！！！！！！
 * 在本库中如果使用mutex，要考虑会被子进程继承的问题
 * 若子进程创建的过程中，mutex是lock状态，那么子进程会死锁
 * 因为父进程解除的只会是自己的mutex，解除不了被子进程继承过去的mutex
*/

char *GLIBC_VERSION[] =
{
        "GLIBC_2.2.5",
        "GLIBC_2.17",
};

void initSymbolAddr(void)
{
    for(int i=0;i<sizeof(GLIBC_VERSION)/sizeof(GLIBC_VERSION[0]);++i)
    {
        real_dlsym = (fc_dlsym)dlvsym(REAL_LIBC, "dlsym", GLIBC_VERSION[i]);
        if(real_dlsym)  break;
    }

    // 屏蔽seccomp机制，因为它的限制会导致我们库中的
    // 某些被限制的系统调用一旦触发，就会被内核杀死
    INIT_PTR(long,prctl,(int __option, ...));
    INIT_PTR(long,seccomp,(unsigned int operation, unsigned int flags, ...));

    // 文件监控及保护
    //      原始文件操作

    INIT_PTR(long,open,(const char *,int,mode_t));
    INIT_PTR(long,open64,(const char *,int,mode_t));
    INIT_PTR(long,openat,(int __fd, const char *__file, int __oflag, .../*mode_t*/));
    INIT_PTR(long,close,(int));
    INIT_PTR(long,rename,(const char *__old, const char *__new));
    INIT_PTR(long,renameat,(int __oldfd, const char *__old, int __newfd,const char *__new));
    INIT_PTR(long,renameat2,(int __oldfd, const char *__old, int __newfd,const char *__new, unsigned int __flags));
    INIT_PTR(long,unlink,(const char *__name));
    INIT_PTR(long,unlinkat,(int __fd, const char *__name, int __flag));
    //      F系列文件操作
    INIT_PTR(long,fopen,(const char * __filename, const char * __modes));
    INIT_PTR(long,freopen,(const char * __filename, const char * __modes, void * __stream));
    INIT_PTR(long,fopen64,(const char * __filename, const char * __modes));
    INIT_PTR(long,freopen64,(const char * __filename, const char * __modes, void * __stream));
    INIT_PTR(long,fclose,(void *__stream));
    INIT_PTR(long,fcloseall,(void));
    // 进程防护
    INIT_PTR(long,execve,(const char *__path, char *const __argv[], char *const __envp[]));
    INIT_PTR(long,execveat,(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags));
    INIT_PTR(long,fexecve,(int __fd, char *const __argv[], char *const __envp[]));
    // 驱动防护
    INIT_PTR(long,finit_module,(int fd, const char *param_values,int flags));
    INIT_PTR(long,init_module,(const void *module_image, unsigned long len, const char *param_values, const struct module *mod));
    INIT_PTR(long,delete_module,(const char *name_user, unsigned int flags));
    INIT_PTR(long,kill,(__pid_t __pid, int __sig));
    // syscall 似乎有点特殊，有时候会段错误
    INIT_PTR(long, syscall,(long int __sysno, ...));
}
// 查询并初始化真实函数地址
__attribute ((constructor)) void plInit(void)
{
    initSymbolAddr();
    const char *mdir = "/tmp/nhook/";
    char lg[64] = {0};
    snprintf(lg,sizeof(lg)-1,"%splog",mdir);
    int ret = mkdir(mdir,0777);
    if(ret == 0 || errno == EEXIST)
    {
        // 打开日志 && 创建一个文件用于互斥锁
        if(real_open)
            gLogFd = real_open(lg,O_CREAT|O_WRONLY|O_APPEND,0777);
        else if(real_open64)
            gLogFd = real_open64(lg,O_CREAT|O_WRONLY|O_APPEND,0777);
        else
            gLogFd = -1;
        if(gLogFd >= 0)
            chmod(lg,0777);
    }
//    // 初始化ipc通信
//    initIpc();
}
// 反初始化
__attribute ((destructor)) void plFini(void)
{
    if(gLogFd >= 0) real_close(gLogFd);
//    unInitIpc();
}
