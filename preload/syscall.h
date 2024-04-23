#pragma once
#include <sys/syscall.h>
#include "define.h"
#include "msyscall.h"
#include "munistd.h"
#define SYMBOL_IS_NOT_FOUND_IN_LIBC   -380
NHOOK_EXPORT long int syscall(long int __sysno, ...);
