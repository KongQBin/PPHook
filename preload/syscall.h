#pragma once
#include <sys/syscall.h>
#include "define.h"
#include "msyscall.h"
#include "munistd.h"
#define FUNC_IS_NOT_FOUND   -99
NHOOK_EXPORT long int syscall(long int __sysno, ...);
