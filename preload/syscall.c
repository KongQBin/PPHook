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
long directCall(long int __sysno, ...)
{
    long ret = 0;
    va_list va_args;
    long argv[7] = { 0 };
    va_start(va_args,__sysno);
    for(int i=0;i<sizeof(argv)/sizeof(argv[0]);++i)
        argv[i] = va_arg(va_args, long);
    if(real_syscall)
        ret = real_syscall(__sysno,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
    else
        ret = msyscall(__sysno,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
    va_end(va_args);
    return ret;

}
long syscall(long int __sysno, ...)
{
    long ret = 0;
    va_list va_args;
    long argv[7] = { 0 };
    va_start(va_args,__sysno);
    for(int i=0;i<sizeof(argv)/sizeof(argv[0]);++i)
        argv[i] = va_arg(va_args, long);

    switch (__sysno) {
#if defined(__x86_64__)
        CaseSysno(open,argv[0],argv[1],argv[2]);
        CaseSysno(rename,argv[0],argv[1]);
        CaseSysno(unlink,argv[0]);
#endif
        CaseSysno(prctl,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
        CaseSysno(seccomp,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
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
        ret = directCall(__sysno,argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
        break;
    }
    }
    va_end(va_args);
    return ret;
}
#pragma GCC diagnostic pop
