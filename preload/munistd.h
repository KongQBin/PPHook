#pragma once
#ifndef F_OK
# define    F_OK        0
#endif
#ifndef O_CREAT
# define    O_CREAT     0100	/* Not fcntl.  */
#endif
#ifndef O_RDONLY
# define    O_RDONLY	00
#endif
#ifndef O_WRONLY
# define    O_WRONLY	01
#endif
#ifndef O_RDWR
# define O_RDWR		    02
#endif
#ifndef O_ACCMODE
# define O_ACCMODE      03
#endif
#ifndef O_TRUNC
# define O_TRUNC        01000	/* not fcntl */
#endif
#ifndef O_APPEND
# define    O_APPEND	02000
#endif
#ifndef AT_FDCWD
# define    AT_FDCWD	-100
#endif

extern ssize_t read (int __fd, void *__buf, size_t __n);
extern ssize_t write (int __fd, const void *__buf, size_t __n);
extern ssize_t readlink (const char *__restrict __path,char *__restrict __buf, size_t __len);
extern __pid_t getpid (void);
extern __pid_t gettid (void);
extern int sprintf (char *__restrict __s, const char *__restrict __format, ...);
extern int snprintf (char *__restrict __s, size_t __maxlen, const char *__restrict __format, ...);
extern int ftruncate (int __fd, __off_t __length);
extern int access (const char *__name, int __type);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
extern long close(int __fd);
extern long open(const char *path, int oflag, mode_t mode);
extern long openat (int __fd, const char *__file, int __oflag, ...);
extern long rename(const char *__old, const char *__new);
extern long renameat(int __oldfd, const char *__old, int __newfd, const char *__new);
extern long renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned int __flags);
extern long unlink (const char *__name);
extern long unlinkat (int __fd, const char *__name, int __flag);
extern long execveat(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags);
extern long execve(const char *__path, char *const __argv[], char *const __envp[]);
extern long fexecve(int __fd, char *const __argv[], char *const __envp[]);
extern long init_module(const void *module_image, unsigned long len, const char *param_values, const struct module *mod);
extern long finit_module(int fd, const char *param_values,int flags);
extern long delete_module(const char *name_user, unsigned int flags);
extern long kill(__pid_t __pid, int __sig);
#pragma GCC diagnostic pop


