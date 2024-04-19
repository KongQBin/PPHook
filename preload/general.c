#include "general.h"
int gLogFd = -1;
#define SYSMON_PATH_MAX 256
static inline int mreadlink(char *originPath, char **targetPath, size_t *len)
{
    int mlen = 0, olen = 0;
    while(1)
    {
        *targetPath = calloc(1,mlen + SYSMON_PATH_MAX);
        if(!*targetPath) return -1;
        olen = mlen + SYSMON_PATH_MAX;
        mlen = readlink(originPath, *targetPath, olen);
        if(mlen < olen) break;
        else free(*targetPath);
    }
    *len = mlen;
    return mlen;
}

int getCwd(char **cwd, size_t *len)
{
    char cwdPath[64] = { 0 };
    sprintf(cwdPath,"/proc/%llu/task/%llu/cwd",getpid(),gettid());
    return mreadlink(cwdPath,cwd,len);
}

int getFdPath(char **path, size_t *len, int fd)
{
    char fdPath[128] = { 0 };
    sprintf(fdPath,"/proc/%llu/task/%llu/fd/%d",getpid(),gettid(),fd);
    return mreadlink(fdPath,path,len);
}

int getExe(char **exe, size_t *len)
{
    char exePath[64] = { 0 };
    sprintf(exePath,"/proc/%u/exe",getpid());
    return mreadlink(exePath,exe,len);
}

void nhookputlog(const char *funcName,const char *msg)
{
    char buf[2048] = {0};
    char *exe = NULL;
    size_t exeLen = 0;
    getExe(&exe,&exeLen);
    snprintf(buf,sizeof(buf)-1,"func = %s\texe = %s\topt = %s",funcName,exe,msg);
    // 在hook系统开机时的close函数时 write调用会导致后台服务启动但开机黑屏
    if(gLogFd >=0 && !strstr(funcName,"close")) write(gLogFd,buf,strlen(buf));
    if(exe) free(exe);
}
