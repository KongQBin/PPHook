#pragma once
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
extern long rename(const char *__old, const char *__new);
extern long renameat(int __oldfd, const char *__old, int __newfd, const char *__new);
extern long renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned int __flags);
extern long execveat(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags);
extern long execve(const char *__path, char *const __argv[], char *const __envp[]);
#pragma GCC diagnostic pop

#ifndef F_OK
# define    F_OK        0
#endif
#ifndef O_CREAT
# define    O_CREAT     0100	/* Not fcntl.  */
#endif
#ifndef O_RDWR
# define O_RDWR		     02
#endif
#ifndef O_WRONLY
# define    O_WRONLY	01
#endif
#ifndef O_APPEND
# define    O_APPEND	02000
#endif
