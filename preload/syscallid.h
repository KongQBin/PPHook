#pragma once
#if defined(__i386__)           // x86
#ifndef __NR_finit_module
#define __NR_finit_module 350
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 353
#endif
#ifndef __NR_execveat
#define __NR_execveat 358
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 354
#endif
#ifndef __NR_prctl
#define __NR_prctl 172
#endif
#elif defined(__x86_64__)       // x64
#ifndef __NR_finit_module
#define __NR_finit_module 313
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 316
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif
#ifndef __NR_prctl
#define __NR_prctl 157
#endif
#elif defined(__arm__)          // arm32
#elif defined(__aarch64__) || defined(__ARM64__)    // arm64

#elif defined(__loongarch__) || defined(__mips64__)

#endif
