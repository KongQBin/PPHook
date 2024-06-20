#pragma once
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "munistd.h"

extern int gLogFd;
typedef struct _defaultdata
{
    pid_t pid;
    pid_t tid;
}defaultdata;
void nhookputlog(const char *funcName,const char *msg);
int realPath(char *path, size_t maxLen);
int __getCwd(char **cwd, size_t *len, defaultdata *data);
int __getExe(char **exe, size_t *len, defaultdata *data);
int __getFdPath(char **path, size_t *len, int fd, defaultdata *data);
static inline int _getCwd(char **cwd, size_t *len, defaultdata *data)
{
    data->pid = data->pid ? data->pid : getpid();
    data->tid = data->tid ? data->tid : mgettid();
    return __getCwd(cwd,len,data);
}
static inline int _getExe(char **exe, size_t *len, defaultdata *data)
{
    data->pid = data->pid ? data->pid : getpid();
    data->tid = data->tid ? data->tid : mgettid();
    return __getExe(exe,len,data);
}
static inline int _getFdPath(char **path, size_t *len, int fd, defaultdata *data)
{
    data->pid = data->pid ? data->pid : getpid();
    data->tid = data->tid ? data->tid : mgettid();
    return __getFdPath(path,len,fd,data);
}
#define getCwd(cwd,len,...) _getCwd(cwd,len,&((defaultdata){__VA_ARGS__}))
#define getExe(exe,len,...) _getExe(exe,len,&((defaultdata){__VA_ARGS__}))
#define getFdPath(path,len,fd,...) _getFdPath(path,len,fd,&((defaultdata){__VA_ARGS__}))
