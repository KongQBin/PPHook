#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "munistd.h"
#include "general.h"
#include "ipclient.h"

int initRenameMsg(const int __oldfd, const char *__old, const int __newfd,
                    const char *__new, MonitorMsg *msg)
{
    msg->type = M_FILE_MONITOR;
    // fd == AT_FDCWD (此时有可能是相对路径也可能是绝对路径)
    // 当非绝对路径时，需要获取当前运行路径与其做拼接
    char *dirPath = NULL;
    size_t dirPathLen = 0;
    if(__old[0] != '/')
    {
        if(__oldfd != AT_FDCWD)
            getFdPath(&dirPath,&dirPathLen,__oldfd);
        else
            getCwd(&dirPath,&dirPathLen);
        if(dirPath)
        {
            strncat(msg->data.fmd.filepath,dirPath,sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
            strncat(msg->data.fmd.filepath,"/",sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
            free(dirPath);
            dirPath = NULL;
            dirPathLen = 0;
        }
    }
    if(__new[0] != '/')
    {
        if(__newfd != AT_FDCWD)
            getFdPath(&dirPath,&dirPathLen,__newfd);
        else
            getCwd(&dirPath,&dirPathLen);
        if(dirPath)
        {
            strncat(msg->data.fmd.filepath2,dirPath,sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
            strncat(msg->data.fmd.filepath2,"/",sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
            free(dirPath);
            dirPath = NULL;
            dirPathLen = 0;
        }
    }
    // 拼接前面处理好的路径
    strncat(msg->data.fmd.filepath,__old,sizeof(msg->data.fmd.filepath)-strlen(msg->data.fmd.filepath)-1);
    strncat(msg->data.fmd.filepath2,__new,sizeof(msg->data.fmd.filepath2)-strlen(msg->data.fmd.filepath2)-1);
    realPath(msg->data.fmd.filepath,sizeof(msg->data.fmd.filepath));
    realPath(msg->data.fmd.filepath2,sizeof(msg->data.fmd.filepath2));
    return 0;
}

int initOpenMsg(const int __fd, const char *__file, MonitorMsg *msg)
{
    msg->type = M_ACTIVE_DEFENSE;
    if(__file[0] != '/')
    {
        char *dirPath = NULL;
        size_t dirPathLen = 0;
        if(__fd != AT_FDCWD)
            getFdPath(&dirPath,&dirPathLen,__fd);
        else
            getCwd(&dirPath,&dirPathLen);
        if(dirPath)
        {
            snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,dirPath);
            strncat(msg->data.add.filepath,"/",sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
            free(dirPath);
        }
    }
    strncat(msg->data.add.filepath,__file,sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
    realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
    return 0;
}

int initUnlinkMsg(const int __fd, const char *__name, MonitorMsg *msg)
{
    msg->type = M_ACTIVE_DEFENSE;
    if(__name[0] != '/')
    {
        char *dirPath = NULL;
        size_t dirPathLen = 0;
        if(__fd != AT_FDCWD)
            getFdPath(&dirPath,&dirPathLen,__fd);
        else
            getCwd(&dirPath,&dirPathLen);
        if(dirPath)
        {
            snprintf(msg->data.add.filepath,sizeof(msg->data.add.filepath)-1,dirPath);
            strncat(msg->data.add.filepath,"/",sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
            free(dirPath);
        }
    }
    strncat(msg->data.add.filepath,__name,sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
    realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
    return 0;
}

int initExecveMsg(const int __fd, const char *__path, MonitorMsg *msg)
{
    msg->type = M_ACTIVE_DEFENSE;
    if(__path[0] != '/')
    {
        char *dirPath = NULL;
        size_t dirPathLen = 0;
        if(__fd != AT_FDCWD)
            getFdPath(&dirPath,&dirPathLen,__fd);
        else
            getCwd(&dirPath,&dirPathLen);
        if(dirPath)
        {
            strncat(msg->data.add.filepath,dirPath,sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
            strncat(msg->data.add.filepath,"/",sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
            free(dirPath);
        }
    }
    strncat(msg->data.add.filepath,__path,sizeof(msg->data.add.filepath)-strlen(msg->data.add.filepath)-1);
    realPath(msg->data.add.filepath,sizeof(msg->data.add.filepath));
    return 0;
}
