#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "general.h"
#include "ipclient.h"
#include "setwhite.h"
#include "com.h"

typedef struct sysinfo sysinfo_t;
int gUptime = 0;
int uptime()
{
    // 开机时间
    if(!gUptime)
    {
        sysinfo_t info;
        sysinfo(&info);
        // 判断开机时间是否大于60秒
        if(info.uptime <= 60)
            gUptime = 0;
        else
            gUptime = 1;
    }
    return !gUptime;
}

extern int ignoreDir(const char* path);
extern PCOMMON_DATA initCloseMsg(const int __fd);
extern PCOMMON_DATA initFexecveMsg(const int __fd);
extern PCOMMON_DATA initFmoduleMsg(const int __fd);
extern PCOMMON_DATA initKillMsg(__pid_t *__pid, int *__sig);
extern PCOMMON_DATA initModuleMsg(const char *path, int len);
extern PCOMMON_DATA initDeleteModuleMsg(const char *path, int len);
extern PCOMMON_DATA initOpenMsg(const int __fd, const char *__file, TRACE_POINT tp);
extern PCOMMON_DATA initUnlinkMsg(const int __fd, const char *__name, TRACE_POINT tp);
extern PCOMMON_DATA initExecveMsg(const int __fd, const char *__path, TRACE_POINT tp);
extern PCOMMON_DATA initRenameMsg(const int __oldfd, const char *__old, const int __newfd,
                           const char *__new, TRACE_POINT tp);

NHOOK_EXPORT long rename (const char *__old, const char *__new)
{
    TRACE_POINT tp = ZyTracePointRename;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initRenameMsg(AT_FDCWD,__old,AT_FDCWD,__new,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_rename ? real_rename(__old,__new) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long renameat (int __oldfd, const char *__old, int __newfd,
                    const char *__new)
{
    TRACE_POINT tp = ZyTracePointRenameat;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initRenameMsg(__oldfd,__old,__newfd,__new,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_renameat ? real_renameat(__oldfd,__old,__newfd,__new) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long renameat2 (int __oldfd, const char *__old, int __newfd,
                     const char *__new, unsigned int __flags)
{
    TRACE_POINT tp = ZyTracePointRenameat2;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    // renameat2这个系统调用与renameat()的不同之处在于它有新的flags参数;如果flags为0，则renameat2()的行为与renameat()完全相同。
    // 反之，如果flags包含RENAME_EXCHANGE，则不会删除位于newname的现有文件，相反，它将被重命名为oldname。
    // 此处不关注__flags
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initRenameMsg(__oldfd,__old,__newfd,__new,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_renameat2 ? real_renameat2(__oldfd,__old,__newfd,__new,__flags) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long open(const char *path, int oflag, mode_t mode)
{
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!(O_ACCMODE&oflag)) break; //读权限打开
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,path,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_open ? real_open(path,oflag,mode) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long open64(const char *path, int oflag, mode_t mode)
{
    /*
     * open64 函数是对open的扩展，确保支持大文件（即文件大小和偏移量可以超过2GB）。
     * 在64位系统上，open 和 open64 通常是等价的，因为64位系统本身就支持大文件处理。
     * 而在32位系统上，open64 用于明确地要求大文件支持
     */
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!(O_ACCMODE&oflag)) break;
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,path,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_open64 ? real_open64(path,oflag,mode) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long openat(int __fd, const char *__file, int __oflag, .../*mode_t*/)
{
    TRACE_POINT tp = ZyTracePointOpenat;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    mode_t mode;
    va_list va_args;
    va_start(va_args,__oflag);
    mode = va_arg(va_args, mode_t);
    va_end(va_args);
    do
    {
        if(white) break;
        if(!__file) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!(O_ACCMODE&__oflag)) break; //读权限打开
        PCOMMON_DATA data = initOpenMsg(__fd,__file,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_openat ? real_openat(__fd,__file,__oflag,mode) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
int getFdOpenFlag(pid_t gpid, pid_t pid, long fd);
NHOOK_EXPORT long close(int __fd)
{
    TRACE_POINT tp = ZyTracePointClose;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        int openflag = getFdOpenFlag(getpid(),gettid(),__fd);
        if(openflag < 0 || !(O_ACCMODE&openflag)) break;
        PCOMMON_DATA data = initCloseMsg(__fd);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL){}
    return real_close ? real_close(__fd) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long/*FILE**/ fopen (const char * __filename, const char * __modes)
{
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__filename || !__modes) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!strstr(__modes,"w") && !strstr(__modes,"a")) break;
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,__filename,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return real_fopen ? real_fopen(__filename,__modes) : /*NULL*/0;
}
NHOOK_EXPORT long/*FILE**/ freopen (const char * __filename, const char * __modes, void/*FILE*/ * __stream)
{
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__filename || !__modes) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!strstr(__modes,"w") && !strstr(__modes,"a")) break;
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,__filename,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return real_freopen ? real_freopen(__filename,__modes,__stream) : /*NULL*/0;
}
NHOOK_EXPORT long/*FILE**/ fopen64 (const char * __filename, const char * __modes)
{
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__filename || !__modes) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!strstr(__modes,"w") && !strstr(__modes,"a")) break;
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,__filename,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return real_fopen64 ? real_fopen64(__filename,__modes) : /*NULL*/0;
}
NHOOK_EXPORT long/*FILE**/ freopen64 (const char * __filename, const char * __modes, void/*FILE*/ * __stream)
{
    TRACE_POINT tp = ZyTracePointOpen;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__filename || !__modes) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!strstr(__modes,"w") && !strstr(__modes,"a")) break;
        PCOMMON_DATA data = initOpenMsg(AT_FDCWD,__filename,tp);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return real_freopen64 ? real_freopen64(__filename,__modes,__stream) : /*NULL*/0;
}
NHOOK_EXPORT int fclose (void *__stream)
{
    TRACE_POINT tp = ZyTracePointClose;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__stream) break;
        if(!getOnoff(tp)) break;
        int __fd = fileno(__stream);
        int openflag = getFdOpenFlag(getpid(),gettid(),__fd);
        if(openflag < 0 || !(O_ACCMODE&openflag)) break;
        PCOMMON_DATA data = initCloseMsg(__fd);
        if(!data) break;
        if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
            recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL){}
    return real_fclose ? real_fclose(__stream) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

// struct src origin -> kernel
struct linux_dirent64 {
    __uint64_t     d_ino;
    __int64_t      d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char        d_name[];
};

NHOOK_EXPORT int fcloseall (void)
{
    TRACE_POINT tp = ZyTracePointClose;
    CONTROL_INFO cmsg;

    int fd = -1, readlen = 0;
    char dir[32] = {0}, names[1024] = {0};
    snprintf(dir,sizeof(dir)-1,"/proc/%d/task/%d/fd",getpid(),gettid());
    struct linux_dirent64 *dirp = NULL;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!real_open) break;
        fd = real_open(dir, O_RDONLY, 0);
        if(fd < 0) break;

        while((readlen = getdents64(fd, (struct linux_dirent64 *)names, sizeof(names))) > 0)
        {
            for(char *ptr = names; ptr < names+readlen; ptr += dirp->d_reclen)
            {
                cmsg.tp = tp;
                cmsg.dec = D_ALLOW;
                dirp = (struct linux_dirent64 *)ptr;

                // 获取打开的所有fd
                char *endptr = NULL;
                long tfd = strtol(dirp->d_name,&endptr,10);
                if(dirp->d_name == endptr) continue;        // 转换失败
                if(fd == tfd)              continue;        // fd是我们前面打开的目录
                int openflag = getFdOpenFlag(getpid(),gettid(),tfd);
                if(openflag < 0 || !(O_ACCMODE&openflag)) continue; // flag错误或只读打开
                PCOMMON_DATA data = initCloseMsg(tfd);
                if(!data) continue;
                if(!ignoreDir(data->argvs) && !sendMsg(data) && getBackwait(tp))
                    recvMsg(&cmsg);
                free(data);
                data = NULL;
            }
        }
    }while(0);
    if(fd >= 0 && real_close) real_close(fd);
    return real_fcloseall ? real_fcloseall() : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long unlink(const char *__name)
{
    TRACE_POINT tp = ZyTracePointUnlink;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initUnlinkMsg(AT_FDCWD,__name,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_unlink ? real_unlink(__name) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long unlinkat(int __fd, const char *__name, int __flag)
{
    TRACE_POINT tp = ZyTracePointUnlinkat;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initUnlinkMsg(__fd,__name,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_unlinkat ? real_unlinkat(__fd,__name,__flag) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long execve(const char *__path, char *const __argv[], char *const __envp[])
{
    TRACE_POINT tp = ZyTracePointExecve;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initExecveMsg(AT_FDCWD,__path,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_execve ? real_execve(__path,(char *const*)__argv,(char *const*)__envp) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long execveat(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags)
{
    TRACE_POINT tp = ZyTracePointExecveat;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initExecveMsg(__fd,__path,tp);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_execveat ? real_execveat(__fd,__path,__argv,__envp,__flags) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long fexecve(int __fd, char *const __argv[], char *const __envp[])
{
    TRACE_POINT tp = ZyTracePointExecve;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initFexecveMsg(__fd);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_fexecve ? real_fexecve(__fd,__argv,__envp) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long init_module(const void *module_image, unsigned long len, const char *param_values, const struct module *mod)
{
    TRACE_POINT tp = ZyTracePointInitModule;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!module_image) break;
        if(!real_open || !real_close) break;
        if(!getOnoff(tp)) break;

        // 生成一个临时路径
        char tmpKoPath[64] = { 0 };
        snprintf(tmpKoPath,sizeof(tmpKoPath)-1,"/tmp/jynzfpostmod_%u_%u.ko",getpid(),gettid());
        // 根据驱动内容生成一个临时文件
        int tmpFd = real_open(tmpKoPath,O_CREAT|O_WRONLY|O_TRUNC,0666);
        if(tmpFd >= 0)
        {
            write(tmpFd,module_image,len);
            real_close(tmpFd);
        }
        PCOMMON_DATA data = initModuleMsg(tmpKoPath,strlen(tmpKoPath));
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_init_module ? real_init_module(module_image,len,param_values,mod) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long finit_module(int fd, const char *param_values,int flags)
{
    TRACE_POINT tp = ZyTracePointFinitModule;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initFmoduleMsg(fd);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_finit_module ? real_finit_module(fd,param_values,flags) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
NHOOK_EXPORT long delete_module(const char *name_user, unsigned int flags)
{
    TRACE_POINT tp = ZyTracePointDeleteModule;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!name_user) break;
        if(!getOnoff(tp)) break;
        PCOMMON_DATA data = initDeleteModuleMsg(name_user,strlen(name_user));
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_delete_module ? real_delete_module(name_user,flags) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}
const char *killWhite[] = {
    "init",
    "systemd",
    "kill",
    "pkill",
    "skill",
    "killall",
    "killall5",
};
NHOOK_EXPORT long kill(__pid_t __pid, int __sig)
{
    TRACE_POINT tp = ZyTracePointKill;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__sig) break;       // signal == 0，一般是为了判断进程是否存在
        if(!getOnoff(tp)) break;

        // 判断当前信号发送者
        // 如果是系统服务管理进程，则不监控
        // 否则关机时会阻塞导致无法关机

        // 此处会产生一个问题，如果用systemctl手动去停止被保护的服务，那么进程防护就会失去作用
        // 只能从execve处，获取执行systemctl的参数的形式，来分析用户、恶意程序要停止的服务
        PCOMMON_DATA data = initKillMsg(&__pid,&__sig);
        if(!data) break;
        if(!sendMsg(data) && getBackwait(tp)) recvMsg(&cmsg);
        free(data);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_kill ? real_kill(__pid,__sig) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

