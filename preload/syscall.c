#include "syscall.h"
// 屏蔽类型检查警告
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"

#define CaseSysno(callname,...) \
case __NR_##callname:\
{\
    ret = callname(__VA_ARGS__);\
    break;\
}

void nhookputlog(const char *funcName,const char *msg);
static pthread_mutex_t defaultMutex = PTHREAD_MUTEX_INITIALIZER;
long syscall(long int __sysno, ...)
{
    va_list va_args;
    long argv[7] = { 0 };
    long ret = 0, toSysCall = 0;
    va_start(va_args,__sysno);
    for(int i=0;i<sizeof(argv)/sizeof(argv[0]);++i)
        argv[i] = va_arg(va_args, long);

    switch (__sysno) {
#if defined(__x86_64__)
        CaseSysno(open,argv[0],argv[1],argv[2]);
        CaseSysno(rename,argv[0],argv[1]);
        CaseSysno(unlink,argv[0]);
#endif
        CaseSysno(openat,argv[0],argv[1],argv[2],argv[3]);
        CaseSysno(unlinkat,argv[0],argv[1],argv[2]);
        CaseSysno(close,argv[0]);
        CaseSysno(renameat,argv[0],argv[1],argv[2],argv[3]);
        CaseSysno(renameat2,argv[0],argv[1],argv[2],argv[3],argv[4]);
        CaseSysno(execve,argv[0],argv[1],argv[2]);
        CaseSysno(execveat,argv[0],argv[1],argv[2],argv[3],argv[4]);
        CaseSysno(init_module,argv[0],argv[1],argv[2],argv[3]);
        CaseSysno(finit_module,argv[0],argv[1],argv[2]);
        CaseSysno(delete_module,argv[0],argv[1]);
        CaseSysno(kill,argv[0],argv[1]);
    default:
    {
        toSysCall = 1;
        break;
    }
    }
    // 如果未查询到对应的符号，则以上调用会返回-99
    // 此时消息已经发送完毕，使用syscall函数来处理这些调用
    if(ret == SYMBOL_IS_NOT_FOUND_IN_LIBC) toSysCall = 1;
    if(toSysCall)
    {
        /*
         * 这里面除了放行不关注的系统调用之外,最好什么都不要做，因为可能存在低级的系统调用，会被后续操作影响
         * 例如加打印、内存开辟、写文件之类的操作都有可能影响这次调用
         * 需要添加打印信息的，就做类似上面的转发操作，一般不会出现问题
        */
        if(real_syscall)
            ret = real_syscall(__sysno,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
        else
            ret = msyscall(__sysno,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
//        int tmperr = errno;
//        char buf[1024] = {0};
//        // snprintf会导致奇安信浏览器启动时抛“追踪与中断点陷阱（核心已转储）”，
//        // 原因未深入调查(猜测栈溢出：不使用snprintf时，buf可能被编译器优化掉了，所以不占用栈区空间)
//        snprintf(buf,sizeof(buf)-1,"__sysno = %ld\t%s(%d)\targv1 = %ld\tret = %ld\n",__sysno,strerror(tmperr),tmperr,argv1,ret);
//        nhookputlog("syscall",buf);
//        errno = tmperr;
    }
    va_end(va_args);
    return ret;
}
#pragma GCC diagnostic pop
