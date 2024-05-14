#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "general.h"
#include "ipclient.h"
#include "setwhite.h"

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
extern int initRenameMsg(const int __oldfd, const char *__old, const int __newfd,
                    const char *__new, MonitorMsg *msg);
extern int initOpenMsg(const int __fd, const char *__file, MonitorMsg *msg);
extern int initUnlinkMsg(const int __fd, const char *__name, MonitorMsg *msg);
extern int initExecveMsg(const int __fd, const char *__path, MonitorMsg *msg);

NHOOK_EXPORT long rename (const char *__old, const char *__new)
{
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"rename",sizeof(msg->funcname)-1);
            initRenameMsg(AT_FDCWD,__old,AT_FDCWD,__new,msg);
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_rename ? real_rename(__old,__new) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}


NHOOK_EXPORT long renameat (int __oldfd, const char *__old, int __newfd,
                    const char *__new)
{
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"renameat",sizeof(msg->funcname)-1);
            initRenameMsg(__oldfd,__old,__newfd,__new,msg);
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_renameat ? real_renameat(__oldfd,__old,__newfd,__new) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long renameat2 (int __oldfd, const char *__old, int __newfd,
                     const char *__new, unsigned int __flags)
{
    // renameat2这个系统调用与renameat()的不同之处在于它有新的flags参数;如果flags为0，则renameat2()的行为与renameat()完全相同。
    // 反之，如果flags包含RENAME_EXCHANGE，则不会删除位于newname的现有文件，相反，它将被重命名为oldname。
    // 此处不关注__flags
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__old || !__new) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"renameat2",sizeof(msg->funcname)-1);
            initRenameMsg(__oldfd,__old,__newfd,__new,msg);
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_renameat2 ? real_renameat2(__oldfd,__old,__newfd,__new,__flags) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long open(const char *path, int oflag, mode_t mode)
{
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!path) break;
        if(uptime()) break;
        // 判断是不是我们的内存映射Key
        if(strstr(path,MMAP_PATH)) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initOpenMsg(AT_FDCWD,path,msg);
            strncat(msg->funcname,"open",sizeof(msg->funcname)-1);
            if(!ignoreDir(msg->data.add.filepath) && !sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!path) break;
        if(uptime()) break;
        // 判断是不是我们的内存映射Key
        if(strstr(path,MMAP_PATH)) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initOpenMsg(AT_FDCWD,path,msg);
            strncat(msg->funcname,"open64",sizeof(msg->funcname)-1);
            if(!ignoreDir(msg->data.add.filepath) && !sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    mode_t mode;
    va_list va_args;
    va_start(va_args,__oflag);
    mode = va_arg(va_args, mode_t);
    do
    {
        if(white) break;
        if(!__file) break;
        if(uptime()) break;
        // 判断是不是我们的内存映射Key
        if(strstr(__file,MMAP_PATH)) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initOpenMsg(__fd,__file,msg);
            strncat(msg->funcname,"openat",sizeof(msg->funcname)-1);
            if(!ignoreDir(msg->data.add.filepath) && !sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_openat ? real_openat(__fd,__file,__oflag,mode) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long close(int __fd)
{
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_FILE_MONITOR;
            strncat(msg->funcname,"close",sizeof(msg->funcname)-1);
            char *path = NULL;
            size_t pathLen = 0;
            getFdPath(&path,&pathLen,__fd);
            if(path)
            {
                snprintf(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath)-1,"%s",path);
                realPath(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath));
                if(!ignoreDir(msg->data.fmd.filepath) && msg->data.fmd.filepath[0] == '/')
                    sendMsg(msg);
                free(path);
            }
            free(msg);
        }
    }while(0);
    return real_close ? real_close(__fd) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

NHOOK_EXPORT long unlink(const char *__name)
{
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initUnlinkMsg(AT_FDCWD,__name,msg);
            strncat(msg->funcname,"unlink",sizeof(msg->funcname)-1);
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!__name) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initUnlinkMsg(__fd,__name,msg);
            strncat(msg->funcname,"unlinkat",sizeof(msg->funcname)-1);
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initExecveMsg(AT_FDCWD,__path,msg);
            strncat(msg->funcname,"execve",sizeof(msg->funcname)-1);
            int sret = sendMsg(msg);
//            printf("sret = %d\n",sret);
            if(!sret)
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(!__path) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            initExecveMsg(__fd,__path,msg);
            strncat(msg->funcname,"execveat",sizeof(msg->funcname)-1);
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_ACTIVE_DEFENSE;
            strncat(msg->funcname,"fexecve",sizeof(msg->funcname)-1);
            char *fdPath = NULL;
            size_t fdPathLen = 0;
            getFdPath(&fdPath,&fdPathLen,__fd);
            if(fdPath)
            {
                snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,"%s",fdPath);
                realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
                free(fdPath);
            }
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!module_image) break;
        if(!getActiveDefense()) break;
        if(!real_open || !real_close) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_ACTIVE_DEFENSE;
            strncat(msg->funcname,"init_module",sizeof(msg->funcname)-1);
            // 生成一个临时路径
            char tmpKoPath[256] = { 0 };
            const char *dPath = "/tmp/jyn_active_defense/";
            if(access(dPath,F_OK) != 0) mkdir(dPath,0666);
            snprintf(tmpKoPath,sizeof(tmpKoPath)-1,"%s_%u_%u.ko",dPath,getpid(),gettid());
            // 根据驱动内容生成一个临时文件
            int tmpFd = real_open(tmpKoPath,O_CREAT|O_WRONLY,0666);
            if(tmpFd >= 0)
            {
                // 清空文件内容(防止文件存在)
                ftruncate(tmpFd,0);
                write(tmpFd,module_image,len);
                real_close(tmpFd);
            }
            // 消息构建
            snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,"%s",tmpKoPath);
            realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_ACTIVE_DEFENSE;
            strncat(msg->funcname,"finit_module",sizeof(msg->funcname)-1);
            char *path = NULL;
            size_t pathLen = 0;
            getFdPath(&path,&pathLen,fd);
            if(path)
            {
                snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,"%s",path);
                realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
                free(path);
                if(!sendMsg(msg))
                    recvMsg(&cmsg);
            }
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!name_user) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_ACTIVE_DEFENSE;
            strncat(msg->funcname,"delete_module",sizeof(msg->funcname)-1);
            snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,"%s",name_user);
            realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
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
    ControlMsg cmsg;
    cmsg.dec = D_ALLOW;
    do
    {
        if(white) break;
        if(uptime()) break;
        if(!__sig) break;       // signal == 0，一般是为了判断进程是否存在
        if(!getActiveDefense()) break;

        // 判断当前信号发送者
        // 如果是系统服务管理进程，则不监控
        // 否则关机时会阻塞导致无法关机

        // 此处会产生一个问题，如果用systemctl手动去停止被保护的服务，那么进程防护就会失去作用
        // 只能从execve处，获取执行systemctl的参数的形式，来分析用户、恶意程序要停止的服务
//        char *exe = NULL;
//        size_t exeLen = 0;
//        getExe(&exe,&exeLen);
//        if(exe)
//        {
//            int b = 0;
//            for(int i=0;i<sizeof(killWhite)/sizeof(killWhite[0]);++i)
//            {
//                if(strstr(exe,killWhite[i]))
//                {
//                    b = 1;
//                    break;
//                }
//            }
//            free(exe);
//            exe = NULL;
//            exeLen = 0;
//            if(b) break;
//        }

        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            msg->type = M_ACTIVE_DEFENSE;
            strncat(msg->funcname,"kill",sizeof(msg->funcname)-1);
            msg->data.add.sig = __sig;
            getExe(&exe,&exeLen,__pid);
            if(exe)
            {
                snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,"%s",exe);
                free(exe);
            }
            // 在此处判断信号目的地是上层交互应用，如果是，则不去监控，也可以解决无法关机的问题
            // 但是，如此一来，我们的上层交互应用就无法被保护了
            if(!sendMsg(msg))
                recvMsg(&cmsg);
            free(msg);
        }
    }while(0);
    if(cmsg.dec == D_DENIAL)
    {
        errno = EPERM;  // 无权限
        return -1;
    }
    return real_kill ? real_kill(__pid,__sig) : SYMBOL_IS_NOT_FOUND_IN_LIBC;
}

