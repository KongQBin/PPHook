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

int __getCwd(char **cwd, size_t *len, defaultdata *data)
{
    char cwdPath[64] = { 0 };
    sprintf(cwdPath,"/proc/%llu/task/%llu/cwd",data->pid,data->tid);
    return mreadlink(cwdPath,cwd,len);
}

int __getFdPath(char **path, size_t *len, int fd, defaultdata *data)
{
    char fdPath[128] = { 0 };
    sprintf(fdPath,"/proc/%llu/task/%llu/fd/%d",data->pid,data->tid,fd);
    return mreadlink(fdPath,path,len);
}

int __getExe(char **exe, size_t *len, defaultdata *data)
{
    char exePath[64] = { 0 };
    sprintf(exePath,"/proc/%u/exe",data->pid);
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

// "/abc//d" -> "/abc/d"
// "/abc/./d" -> "/abc/d"
// "/abc/../d" -> "/d"
void mrealpath(char *cpath)
{
    int tcontinue = 0;
    do
    {
        tcontinue = 0;
        char *tmp1 = NULL, *tmp2 = NULL, *tmp3 = NULL;
        tmp1 = strstr(cpath,"//");     // 去除多余的'/'
        if(tmp1)
        {
            sprintf(tmp1+1,"%s",tmp1+strlen("//"));
            tcontinue = 1;
            continue;
        }
        tmp1 = strstr(cpath,"/./");    // 去除无用的"/./"
        if(tmp1)
        {
            sprintf(tmp1+1,"%s",tmp1+strlen("/./"));
            tcontinue = 1;
            continue;
        }
        tmp1 = strstr(cpath,"/../");   // 翻译"/../"
        if(tmp1)
        {
            tmp2 = tmp1;
            while(tmp2 != cpath)
            {
                -- tmp2;
                if(tmp2[0] == '/')
                {
                    tmp3 = tmp2;
                    break;
                }
            }
            if(tmp3)
            {
                sprintf(tmp3+1,"%s",tmp1+strlen("/../"));
                tcontinue = 1;
                continue;
            }
        }
    }while(tcontinue);
}

int realPath(char *path, size_t maxLen)
{
    int ret = 0;
    char *resolved = realpath(path, NULL);
    if (resolved) {
        snprintf(path,maxLen-1,"%s",resolved);
        free(resolved); // 释放动态分配的内存
    } else {
        ret = -1;
    }
    // realpath 对于不存在的路径不会进行优化
    if(ret || access(path,F_OK))
        mrealpath(path);
    return ret;
}
