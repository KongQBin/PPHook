#pragma once
#include <dlfcn.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/capability.h>

#define NHOOK_EXPORT __attribute__ ((visibility ("default")))
#if defined(RTLD_NEXT)
#  define REAL_LIBC RTLD_NEXT
#else
#  define REAL_LIBC ((void *) -1L)
#endif
#define CREATE_DEF(ret,name,argvs)\
typedef ret (*fc_##name) argvs;\
fc_##name real_##name;
// 批量声明函数指针类型
CREATE_DEF(void*,dlsym,(void *, const char *))
#define INIT_PTR(ret, name, args)  real_##name = (ret (*)args)real_dlsym(REAL_LIBC, #name)

struct module;
struct sockaddr;
extern int gLogFd;
CREATE_DEF(long,open,(const char *,int,mode_t))
CREATE_DEF(long,open64,(const char *,int,mode_t))
CREATE_DEF(long,openat,(int __fd, const char *__file, int __oflag, .../*mode_t*/))
CREATE_DEF(long,close,(int))
CREATE_DEF(long,rename,(const char *__old, const char *__new))
CREATE_DEF(long,renameat,(int __oldfd, const char *__old, int __newfd,const char *__new))
CREATE_DEF(long,renameat2,(int __oldfd, const char *__old, int __newfd,const char *__new, unsigned int __flags))
CREATE_DEF(long,unlink,(const char *__name))
CREATE_DEF(long,unlinkat,(int __fd, const char *__name, int __flag))
CREATE_DEF(long,fopen,(const char * __filename, const char * __modes))
CREATE_DEF(long,freopen,(const char * __filename, const char * __modes, void * __stream))
CREATE_DEF(long,fopen64,(const char * __filename, const char * __modes))
CREATE_DEF(long,freopen64,(const char * __filename, const char * __modes, void * __stream))
CREATE_DEF(long,fclose,(void *__stream))
CREATE_DEF(long,fcloseall,(void))

CREATE_DEF(long,execve,(const char *__path, char *const __argv[], char *const __envp[]))
CREATE_DEF(long,execveat,(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags))
CREATE_DEF(long,fexecve,(int __fd, char *const __argv[], char *const __envp[]))
CREATE_DEF(long,finit_module,(int fd, const char *param_values,int flags))
CREATE_DEF(long,init_module,(const void *module_image, unsigned long len, const char *param_values, const struct module *mod))
CREATE_DEF(long,delete_module,(const char *name_user, unsigned int flags))
CREATE_DEF(long,kill,(__pid_t __pid, int __sig))
// syscall 比较特殊，获取不到地址或者拿获取到的地址进行调用会段错误
// 它是由LIBC进行特殊处理的
CREATE_DEF(long,syscall,(long int __sysno, ...))
// 以下主要给ipcclient用
