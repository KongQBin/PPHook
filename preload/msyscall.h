#pragma once
#include <stdarg.h>
#include <errno.h>
static inline long msyscall(long __sysno, long argv1, long argv2, long argv3, long argv4, long argv5, long argv6, long argv7)
{
    errno = 0;
    long ret = 0;
#if defined(__x86_64__)
    asm volatile (
        "mov %[sysno], %%rax\n\t"
        "mov %[arg1], %%rdi\n\t"
        "mov %[arg2], %%rsi\n\t"
        "mov %[arg3], %%rdx\n\t"
        "mov %[arg4], %%r10\n\t"
        "mov %[arg5], %%r8\n\t"
        "mov %[arg6], %%r9\n\t"
        "syscall\n\t"
        "mov %%rax, %[res]"
        : [res] "=r" (ret)
        : [sysno] "r" (__sysno),
          [arg1] "r" (argv1),
          [arg2] "r" (argv2),
          [arg3] "r" (argv3),
          [arg4] "r" (argv4),
          [arg5] "r" (argv5),
          [arg6] "r" (argv6)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
        );
#elif defined(__aarch64__) || defined(__ARM64__)
    asm volatile (
        "mov x8, %[sysno]\n"
        "mov x0, %[arg1]\n"
        "mov x1, %[arg2]\n"
        "mov x2, %[arg3]\n"
        "mov x3, %[arg4]\n"
        "mov x4, %[arg5]\n"
        "mov x5, %[arg6]\n"
        "mov x6, %[arg7]\n"
        "svc #0x0\n"
        "mov %[res], x0"
        : [res] "=r" (ret)
        : [sysno] "r" (__sysno),
          [arg1] "r" (argv1),
          [arg2] "r" (argv2),
          [arg3] "r" (argv3),
          [arg4] "r" (argv4),
          [arg5] "r" (argv5),
          [arg6] "r" (argv6),
          [arg7] "r" (argv7)
        : "x8", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "memory"
        );
#endif
    if(ret < 0)
    {
        errno = -ret;
        ret = -1;
    }
    return ret;
}
//#if defined(__x86_64__)
//#define MSYSCALL(__sysno,argv1,argv2,argv3,argv4,argv5,argv6,argv7)\
//({\
//        errno = 0;\
//        long retval = 0;\
//        asm volatile ( \
//                      "mov %[sysno], %%rax\n\t" \
//                      "mov %[arg1], %%rdi\n\t" \
//                      "mov %[arg2], %%rsi\n\t" \
//                      "mov %[arg3], %%rdx\n\t" \
//                      "mov %[arg4], %%r10\n\t" \
//                      "mov %[arg5], %%r8\n\t" \
//                      "mov %[arg6], %%r9\n\t" \
//                      "syscall\n\t" \
//                      "mov %%rax, %[res]" \
//                      : [res] "=r" (retval) \
//                      : [sysno] "r" (__sysno), \
//                            [arg1] "r" (argv1), \
//                                [arg2] "r" (argv2), \
//                                    [arg3] "r" (argv3), \
//                                        [arg4] "r" (argv4), \
//                                            [arg5] "r" (argv5), \
//                                                [arg6] "r" (argv6) \
//                      : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory" \
//            ); \
//        if(retval < 0)\
//    {\
//            errno = -retval;\
//            /*retval = -1;*/\
//    }\
//        retval;\
//});
//#elif defined(__aarch64__) || defined(__ARM64__)
//#define MSYSCALL(__sysno,argv1,argv2,argv3,argv4,argv5,argv6,argv7)\
//({\
//        errno = 0;\
//        long retval = 0;\
//        asm volatile (\
//                     "mov x8, %[sysno]\n"\
//                     "mov x0, %[arg1]\n"\
//                     "mov x1, %[arg2]\n"\
//                     "mov x2, %[arg3]\n"\
//                     "mov x3, %[arg4]\n"\
//                     "mov x4, %[arg5]\n"\
//                     "mov x5, %[arg6]\n"\
//                     "mov x6, %[arg7]\n"\
//                     "svc #0x0\n"\
//                     "mov %[res], x0"\
//                     : [res] "=r" (retval)\
//                     : [sysno] "r" (__sysno),\
//                           [arg1] "r" (argv1),\
//                               [arg2] "r" (argv2),\
//                                   [arg3] "r" (argv3),\
//                                       [arg4] "r" (argv4),\
//                                           [arg5] "r" (argv5),\
//                                               [arg6] "r" (argv6),\
//                                                   [arg7] "r" (argv7)\
//                     : "x8", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "memory"\
//            );\
//        if(retval < 0)\
//    {\
//            errno = -retval;\
//            /*retval = -1;*/\
//    }\
//        retval;\
//});
//#endif
