#pragma once
#include <sys/syscall.h>
#include "define.h"
#include "msyscall.h"
#include "munistd.h"
#include "syscallid.h"
#define SYMBOL_IS_NOT_FOUND_IN_LIBC   -1
long directCall(long int __sysno, ...);
NHOOK_EXPORT long int syscall(long int __sysno, ...);
