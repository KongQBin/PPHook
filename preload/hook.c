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

#define ToSysCall(func,sysno,ceret,...) \
({ \
long ret = -1; \
if(func) \
    ret = func(__VA_ARGS__); \
else \
{ \
    if(sysno >= 0) \
        ret = directCall(sysno,##__VA_ARGS__); \
    else \
        ret = ceret; \
} \
ret; \
})

NHOOK_EXPORT long prctl(int __option, ...)
{
    int ret = -1;
    va_list va_args;
    long argv[7] = { 0 };
    va_start(va_args,__option);
    for(int i=0;i<sizeof(argv)/sizeof(argv[0]);++i)
        argv[i] = va_arg(va_args, long);
    // PR_SET_NO_NEW_PRIVS会导致DNS缓存服务(systemd-resolved)启动失败
    // 再者，我们的hook中不需要提权，故忽略即可
    if(/*PR_SET_NO_NEW_PRIVS != __option && */PR_GET_SECCOMP != __option
        && PR_SET_SECCOMP != __option)
        ret = ToSysCall(real_prctl,__NR_prctl,-1,__option,argv[0],
                        argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
    else
    {
        ret = -1;
        errno = EPERM;
    }
    va_end(va_args);
    return ret;
}

NHOOK_EXPORT long seccomp(unsigned int operation, unsigned int flags, ...)
{
    int ret = -1;
    va_list va_args;
    long argv[7] = { 0 };
    va_start(va_args,flags);
    for(int i=0;i<sizeof(argv)/sizeof(argv[0]);++i)
        argv[i] = va_arg(va_args, long);
    if(SECCOMP_SET_MODE_FILTER != operation)
        ret = ToSysCall(real_seccomp,__NR_seccomp,-1,operation,flags,
                        argv[0],argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
    else
    {
        ret = -1;
        errno = EPERM;
    }
    va_end(va_args);
    return ret;
}

extern int ignoreDir(const char* path);
extern PCOMMON_DATA initDup2Msg(const int __fd);
extern PCOMMON_DATA initDup3Msg(const int ofd, const int nfd);
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
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        /////////////////////////////////////
        /// 还需要增加一个对seccomp开关的判断
        ///   避免对方是静态链接的seccomp库
        /// /////////////////////////////////
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        data = initRenameMsg(AT_FDCWD,__old,AT_FDCWD,__new,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_rename,__NR_rename,-1,__old,__new);
}
NHOOK_EXPORT long renameat (int __oldfd, const char *__old, int __newfd,
                    const char *__new)
{
    TRACE_POINT tp = ZyTracePointRenameat;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        data = initRenameMsg(__oldfd,__old,__newfd,__new,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_renameat,__NR_renameat,-1,__oldfd,__old,__newfd,__new);
}
NHOOK_EXPORT long renameat2 (int __oldfd, const char *__old, int __newfd,
                     const char *__new, unsigned int __flags)
{
    // renameat2这个系统调用与renameat()的不同之处在于它有新的flags参数;如果flags为0，则renameat2()的行为与renameat()完全相同。
    // 反之，如果flags包含RENAME_EXCHANGE，则不会删除位于newname的现有文件，相反，它将被重命名为oldname。
    // 此处不关注__flags
    TRACE_POINT tp = ZyTracePointRenameat2;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getOnoff(tp)) break;
        data = initRenameMsg(__oldfd,__old,__newfd,__new,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_renameat2,__NR_renameat2,-1,__oldfd,__old,__newfd,__new,__flags);
}

NHOOK_EXPORT long open(const char *path, int oflag, mode_t mode)
{
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,path,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_open,__NR_open,-1,path,oflag,mode);
}
NHOOK_EXPORT long open64(const char *path, int oflag, mode_t mode)
{
    /*
     * open64 函数是对open的扩展，确保支持大文件（即文件大小和偏移量可以超过2GB）。
     * 在64位系统上，open 和 open64 通常是等价的，因为64位系统本身就支持大文件处理。
     * 而在32位系统上，open64 用于明确地要求大文件支持
     */
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,path,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_open64,__NR_open,-1,path,oflag,mode);
}
NHOOK_EXPORT long openat(int __fd, const char *__file, int __oflag, .../*mode_t*/)
{
    TRACE_POINT tp = ZyTracePointOpenat;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(__fd,__file,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_openat,__NR_openat,-1,__fd,__file,__oflag,mode);
}
extern __thread int tGClientSocket;
int getFdOpenFlag(pid_t gpid, pid_t pid, long fd);
NHOOK_EXPORT long close(int __fd)
{
    int ret = -1;
    TRACE_POINT tp = ZyTracePointClose;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        int openflag = getFdOpenFlag(getpid(),mgettid(),__fd);
        if(openflag < 0 || !(O_ACCMODE&openflag)) break;
        data = initCloseMsg(__fd);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL){}
    ret = ToSysCall(real_close,__NR_close,-1,__fd);
    if(__fd == tGClientSocket) tGClientSocket = -1; /*使下次使用socket会被重新初始化*/
    return ret;
}
// 暂时先复用Close的枚举
// dup2的newfd如果是打开的状态，那么会被自动关闭
NHOOK_EXPORT long dup2(int oldfd, int newfd)
{
    int ret = -1;
    TRACE_POINT tp = ZyTracePointDup2;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        // 如果newfd没被打开，那么此处会返回错误，然后退出
        int openflag = getFdOpenFlag(getpid(),mgettid(),newfd);
        if(openflag < 0 || !(O_ACCMODE&openflag)) break;
        data = initDup2Msg(newfd);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL){}
    ret = ToSysCall(real_dup2,__NR_dup2,-1,oldfd,newfd);
    if(newfd == tGClientSocket) tGClientSocket = -1; /*使下次使用socket会被重新初始化*/
    return ret;
}
// dup3是dup2的增强版
// 同dup2一样newfd如果已经被打开则会自动关闭
// flags代表的是修改被复制的oldfd的标识，有可能会涉及权限问题
NHOOK_EXPORT long dup3(int oldfd, int newfd, int flags)
{
    int ret = -1;
    TRACE_POINT tp = ZyTracePointDup3;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        // 判断哪些消息需要发往上层
        int oflags = 1,nflags = 1;
        // 如果newfd没被打开，那么此处会返回错误，然后退出
        nflags = getFdOpenFlag(getpid(),mgettid(),newfd);
        if(nflags < 0 || !(O_ACCMODE&nflags)) nflags = 0;
        oflags = !(O_ACCMODE&flags) ? 0 : 1;
        data = initDup3Msg(oflags?oldfd:-1,nflags?newfd:-1);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    else
    {
        ret = ToSysCall(real_dup3,__NR_dup3,-1,oldfd,newfd,flags);
        if(newfd == tGClientSocket) tGClientSocket = -1; /*使下次使用socket会被重新初始化*/
        return ret;
    }
}

NHOOK_EXPORT long/*FILE**/ fopen (const char * __filename, const char * __modes)
{
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,__filename,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return ToSysCall(real_fopen,-1,0,__filename,__modes);
}
NHOOK_EXPORT long/*FILE**/ freopen (const char * __filename, const char * __modes, void/*FILE*/ * __stream)
{
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,__filename,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return ToSysCall(real_freopen,-1,0,__filename,__modes,__stream);
}
NHOOK_EXPORT long/*FILE**/ fopen64 (const char * __filename, const char * __modes)
{
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,__filename,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return ToSysCall(real_fopen64,-1,0,__filename,__modes);
}
NHOOK_EXPORT long/*FILE**/ freopen64 (const char * __filename, const char * __modes, void/*FILE*/ * __stream)
{
    TRACE_POINT tp = ZyTracePointOpen;
    PCOMMON_DATA data = NULL;
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
        data = initOpenMsg(AT_FDCWD,__filename,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return /*NULL*/0;
    }
    return ToSysCall(real_freopen64,-1,0,__filename,__modes,__stream);
}
NHOOK_EXPORT long fclose (void *__stream)
{
    int ret = -1;
    TRACE_POINT tp = ZyTracePointClose;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    int __fd = -1;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__stream) break;
        if(!getOnoff(tp)) break;
        __fd = fileno(__stream);
        int openflag = getFdOpenFlag(getpid(),mgettid(),__fd);
        if(openflag < 0 || !(O_ACCMODE&openflag)) break;
        data = initCloseMsg(__fd);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL){}
    ret = ToSysCall(real_fclose,-1,-1,__stream);
    if(__fd == tGClientSocket) tGClientSocket = -1; /*使下次使用socket会被重新初始化*/
    return ret;
}

// struct src origin -> kernel
struct linux_dirent64 {
    __uint64_t     d_ino;
    __int64_t      d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char        d_name[];
};

// 正常情况下，fcloseall只会关闭利用fopen打开的文件不会关闭open打开的文件
// 但我们在此处无法分辨文件是否是open打开的还是被fopen打开的，所以我们此处会遍历所有的fd进行上报
// 而且需要重新初始化我们的socket，因为我们的socket可能会被fdopen转换成FILE，从而可以被fcloseall关闭
NHOOK_EXPORT long fcloseall (void)
{
    TRACE_POINT tp = ZyTracePointClose;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;

    int ret = 0;
    int reinit = 0;
    int fd = -1, readlen = 0;
    char dir[64] = {0}, names[1024] = {0};
    snprintf(dir,sizeof(dir)-1,"/proc/%d/task/%d/fd",getpid(),mgettid());
    struct linux_dirent64 *dirp = NULL;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        if(!real_open) break;
        fd = real_open(dir, O_RDONLY, 0);
        if(fd < 0) break;

        while((readlen = mgetdents64(fd, (struct linux_dirent64 *)names, sizeof(names))) > 0)
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
                if(fd == tGClientSocket)   reinit = 1;
                int openflag = getFdOpenFlag(getpid(),mgettid(),tfd);
                if(openflag < 0 || !(O_ACCMODE&openflag)) continue; // flag错误或只读打开
                data = initCloseMsg(tfd);
                toInteractive(data,&cmsg);
                data = NULL;
            }
        }
    }while(0);
    if(fd >= 0 && real_close) real_close(fd);
    ret = ToSysCall(real_fcloseall,-1,-1);
    // 此时我们用来通讯的fd也可能被关闭了
    if(reinit)  unInitIpc();/*反初始化我们的socket，使下次使用socket会被重新初始化*/
    return ret;
}
// PS: 去除底层的过滤

NHOOK_EXPORT long unlink(const char *__name)
{
    TRACE_POINT tp = ZyTracePointUnlink;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initUnlinkMsg(AT_FDCWD,__name,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_unlink,__NR_unlink,-1,__name);
}

NHOOK_EXPORT long unlinkat(int __fd, const char *__name, int __flag)
{
    TRACE_POINT tp = ZyTracePointUnlinkat;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initUnlinkMsg(__fd,__name,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_unlinkat,__NR_unlinkat,-1,__fd,__name,__flag);
}
NHOOK_EXPORT long execve(const char *__path, char *const __argv[], char *const __envp[])
{
    TRACE_POINT tp = ZyTracePointExecve;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initExecveMsg(AT_FDCWD,__path,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    // 此处的unInit是个容错
    // 主要是为了防止vfork时创建的socket在返回到主进程失效的问题
    // 1.期间子进程并未主动close该socket
    // 2.在创建socket时，主动取消FD_CLOEXEC也未生效
    // 3.vfork.log是在200M的日志文件中排查截取出的问题片段，片段中间并未删除任何内容
    // 4.如果后期对性能影响较大，可以再根据日志找出详细原因
    unInitIpc();
    return ToSysCall(real_execve,__NR_execve,-1,__path,__argv,__envp);
}
NHOOK_EXPORT long execveat(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags)
{
    TRACE_POINT tp = ZyTracePointExecveat;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initExecveMsg(__fd,__path,tp);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    unInitIpc();
    return ToSysCall(real_execveat,__NR_execveat,-1,__fd,__path,__argv,__envp,__flags);
}
NHOOK_EXPORT long fexecve(int __fd, char *const __argv[], char *const __envp[])
{
    TRACE_POINT tp = ZyTracePointExecve;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initFexecveMsg(__fd);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    unInitIpc();
    return ToSysCall(real_fexecve,-1,-1,__fd,__argv,__envp);
}
NHOOK_EXPORT long init_module(const void *module_image, unsigned long len, const char *param_values, const struct module *mod)
{
    TRACE_POINT tp = ZyTracePointInitModule;
    PCOMMON_DATA data = NULL;
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
        snprintf(tmpKoPath,sizeof(tmpKoPath)-1,"/tmp/jynzfpostmod_%u_%u.ko",getpid(),mgettid());
        // 根据驱动内容生成一个临时文件
        int tmpFd = real_open(tmpKoPath,O_CREAT|O_WRONLY|O_TRUNC,0666);
        if(tmpFd >= 0)
        {
            write(tmpFd,module_image,len);
            real_close(tmpFd);
        }
        data = initModuleMsg(tmpKoPath,strlen(tmpKoPath));
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_init_module,__NR_init_module,-1,module_image,len,param_values,mod);
}
NHOOK_EXPORT long finit_module(int fd, const char *param_values,int flags)
{
    TRACE_POINT tp = ZyTracePointFinitModule;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getOnoff(tp)) break;
        data = initFmoduleMsg(fd);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_finit_module,__NR_finit_module,-1,fd,param_values,flags);
}

NHOOK_EXPORT long delete_module(const char *name_user, unsigned int flags)
{
    TRACE_POINT tp = ZyTracePointDeleteModule;
    PCOMMON_DATA data = NULL;
    CONTROL_INFO cmsg;
    cmsg.dec = D_ALLOW;
    cmsg.tp = tp;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!name_user) break;
        if(!getOnoff(tp)) break;
        data = initDeleteModuleMsg(name_user,strlen(name_user));
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_delete_module,__NR_delete_module,-1,name_user,flags);
}

NHOOK_EXPORT long kill(__pid_t __pid, int __sig)
{
    TRACE_POINT tp = ZyTracePointKill;
    PCOMMON_DATA data = NULL;
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
        data = initKillMsg(&__pid,&__sig);
        toInteractive(data,&cmsg);
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return ToSysCall(real_kill,__NR_kill,-1,__pid,__sig);
}

