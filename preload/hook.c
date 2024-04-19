#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "general.h"
#include "ipclient.h"
//#include "structmsg.h"

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

int initRenameAtMsg(int __oldfd, const char *__old, int __newfd,
                    const char *__new, MonitorMsg *msg)
{
    if(__old && __new)
    {
        msg->type = M_FILE_MONITOR;
        // -100 = AT_FDCWD (此时有可能是相对路径也可能是绝对路径)
        // 当非绝对路径时，需要获取当前运行路径与其做拼接
        if((__oldfd == -100 && __old[0] != '/')
            || (__newfd == -100 && __new[0] != '/'))
        {
            char *cwd = NULL;
            size_t cwdLen = 0;
            getCwd(&cwd,&cwdLen);
            if(cwd)
            {
                if(__oldfd == -100 && __old[0] != '/')
                    strncat(msg->data.fmd.filepath,cwd,sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
                if(__newfd == -100 && __new[0] != '/')
                    strncat(msg->data.fmd.filepath2,cwd,sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
                free(cwd);
            }
        }
        // 如果 fd != AT_FDCWD，则获取fd所指向的路径
        if(__oldfd != -100 && __old[0] != '/')
        {
            char *dirPath = NULL;
            size_t dirPathLen = 0;
            getFdPath(&dirPath,&dirPathLen,__oldfd);
            if(dirPath)
            {
                strncat(msg->data.fmd.filepath,dirPath,sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
                free(dirPath);
            }
        }
        if(__newfd != -100 && __new[0] != '/')
        {
            char *dirPath = NULL;
            size_t dirPathLen = 0;
            getFdPath(&dirPath,&dirPathLen,__newfd);
            if(dirPath)
            {
                strncat(msg->data.fmd.filepath2,dirPath,sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
                free(dirPath);
            }
        }

        // 拼接前面处理好的路径
        strncat(msg->data.fmd.filepath,"/",sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
        strncat(msg->data.fmd.filepath,__old,sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
        strncat(msg->data.fmd.filepath2,"/",sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
        strncat(msg->data.fmd.filepath2,__new,sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
        realPath(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath));
        realPath(msg->data.fmd.filepath2,sizeof(msg->data.fmd.filepath2));
    }
    return 0;
}

NHOOK_EXPORT long rename (const char *__old, const char *__new)
{
    do
    {
        if(uptime()) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"rename",sizeof(msg->funcname)-1);
            msg->type = M_FILE_MONITOR;
            snprintf(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath)-1,__old);
            snprintf(msg->data.fmd.filepath2,sizeof(msg->data.fmd.filepath2)-1,__new);
            realPath(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath));
            realPath(msg->data.fmd.filepath2,sizeof(msg->data.fmd.filepath2));
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_rename ? real_rename(__old,__new) : FUNC_IS_NOT_FOUND;
}


NHOOK_EXPORT long renameat (int __oldfd, const char *__old, int __newfd,
                    const char *__new)
{
    do
    {
        if(uptime()) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"renameat",sizeof(msg->funcname)-1);
            initRenameAtMsg(__oldfd,__old,__newfd,__new,msg);
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_renameat ? real_renameat(__oldfd,__old,__newfd,__new) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long renameat2 (int __oldfd, const char *__old, int __newfd,
                     const char *__new, unsigned int __flags)
{
    // renameat2这个系统调用与renameat()的不同之处在于它有新的flags参数;如果flags为0，则renameat2()的行为与renameat()完全相同。
    // 反之，如果flags包含RENAME_EXCHANGE，则不会删除位于newname的现有文件，相反，它将被重命名为oldname。
    // 此处不关注__flags
    do{
        if(uptime()) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"renameat2",sizeof(msg->funcname)-1);
            initRenameAtMsg(__oldfd,__old,__newfd,__new,msg);
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_renameat2 ? real_renameat2(__oldfd,__old,__newfd,__new,__flags) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long open(const char *path, int oflag, mode_t mode)
{
    return real_open ? real_open(path,oflag,mode) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long open64(const char *path, int oflag, mode_t mode)
{
    /*
     * open64 函数是对open的扩展，确保支持大文件（即文件大小和偏移量可以超过2GB）。
     * 在64位系统上，open 和 open64 通常是等价的，因为64位系统本身就支持大文件处理。
     * 而在32位系统上，open64 用于明确地要求大文件支持
     */
    return real_open64 ? real_open64(path,oflag,mode) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long close(int __fd)
{
    do
    {
        if(uptime()) break;
        if(!getFileMonitor()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"close",sizeof(msg->funcname)-1);
            char *path = NULL;
            size_t pathLen = 0;
            getFdPath(&path,&pathLen,__fd);
            msg->type = M_FILE_MONITOR;
            snprintf(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath)-1,path);
            realPath(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath));
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_close ? real_close(__fd) : FUNC_IS_NOT_FOUND;
}


NHOOK_EXPORT long execve(const char *__path, char *const __argv[], char *const __envp[])
{
    do{
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"execve",sizeof(msg->funcname)-1);
            msg->type = M_ACTIVE_DEFENSE;
            snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,__path);
            realPath(msg->data.add.exepath,sizeof(msg->data.add.exepath));
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_execve ? real_execve(__path,(char *const*)__argv,(char *const*)__envp) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long execveat(int __fd, const char *__path, char *const __argv[], char *const __envp[], int __flags)
{
    do{
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"execveat",sizeof(msg->funcname)-1);
            msg->type = M_ACTIVE_DEFENSE;
            char *cwd = NULL, *dPath = NULL;
            size_t cwdLen = 0, dPathLen = 0;
            if(__path && __path[0] != '/')
            {
                if(__fd == -100) // AT_FDCWD
                {
                    getCwd(&cwd,&cwdLen);
                    if(cwd)
                    {
                        snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,cwd);
                        free(cwd);
                    }
                }
                else
                {
                    getFdPath(&dPath,&dPathLen,__fd);
                    if(dPath)
                    {
                        snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,dPath);
                        free(dPath);
                    }
                }
                strncat(msg->data.add.exepath,"/",sizeof(msg->data.add.exepath)-strlen(msg->data.add.exepath)-1);
            }
            strncat(msg->data.add.exepath,__path,sizeof(msg->data.add.exepath)-strlen(msg->data.add.exepath)-1);
            realPath(msg->data.add.exepath,sizeof(msg->data.add.exepath));
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_execveat ? real_execveat(__fd,__path,__argv,__envp,__flags) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long fexecve(int __fd, char *const __argv[], char *const __envp[])
{
    do{
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"fexecve",sizeof(msg->funcname)-1);
            msg->type = M_ACTIVE_DEFENSE;
            char *fdPath = NULL;
            size_t fdPathLen = 0;
            getFdPath(&fdPath,&fdPathLen,__fd);
            if(fdPath)
            {
                snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,fdPath);
                realPath(msg->data.add.exepath,sizeof(msg->data.add.exepath));
                free(fdPath);
            }
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_fexecve ? real_fexecve(__fd,__argv,__envp) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long init_module(const void *module_image, unsigned long len, const char *param_values, const struct module *mod)
{
    do
    {
        if(uptime()) break;
        if(!getActiveDefense()) break;
        if(!real_open || !real_close) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            // 生成一个临时路径
            char tmpKoPath[256] = { 0 };
            const char *dPath = "/tmp/jyn_active_defense/";
            if(access(dPath,F_OK) != 0) mkdir(dPath,0666);
            snprintf(tmpKoPath,sizeof(tmpKoPath)-1,"%s%s.ko",dPath,gettid());
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
            strncat(msg->funcname,"init_module",sizeof(msg->funcname)-1);
            msg->type = M_ACTIVE_DEFENSE;
            snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,tmpKoPath);
            realPath(msg->data.add.exepath,sizeof(msg->data.add.exepath));
            sendMsg(msg);
            free(msg);
        }
    }while(0);
    return real_init_module ? real_init_module(module_image,len,param_values,mod) : FUNC_IS_NOT_FOUND;
}

NHOOK_EXPORT long delete_module(const char *name_user, unsigned int flags)
{
    do
    {
        if(uptime()) break;
        if(!getActiveDefense()) break;
        MonitorMsg *msg = calloc(1,sizeof(MonitorMsg));
        if(msg)
        {
            strncat(msg->funcname,"delete_module",sizeof(msg->funcname)-1);
            msg->type = M_ACTIVE_DEFENSE;
            snprintf(msg->data.add.exepath,sizeof(msg->data.add.exepath)-1,name_user);
            realPath(msg->data.add.exepath,sizeof(msg->data.add.exepath));
            free(msg);
        }
    }while(0);
    return real_delete_module ? real_delete_module(name_user,flags) : FUNC_IS_NOT_FOUND;
}

