#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdarg.h>
#if defined(RTLD_NEXT)
#  define REAL_LIBC RTLD_NEXT
#else
#  define REAL_LIBC ((void *) -1L)
#endif
#define FN(ptr, name)ptr = dlsym(REAL_LIBC, name)

void gethooks(char ***names, void ***funcs, int *len);
