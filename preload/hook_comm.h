#pragma once
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "munistd.h"
#include "general.h"
#include "ipclient.h"
#include "com.h"

int ignoreDir(const char* path);
int getFdOpenFlag(pid_t gpid, pid_t pid, long fd);
PCOMMON_DATA initDup2Msg(const int __fd);
PCOMMON_DATA initOpenMsg(const int __fd, const char *__file, TRACE_POINT tp);
PCOMMON_DATA initUnlinkMsg(const int __fd, const char *__name, TRACE_POINT tp);
PCOMMON_DATA initExecveMsg(const int __fd, const char *__path, TRACE_POINT tp);
PCOMMON_DATA initRenameMsg(const int __oldfd, const char *__old, const int __newfd,
                           const char *__new, TRACE_POINT tp);
