#include "hook_comm.h"

// sudo ls -l /proc/*/fd | grep  "\->" | grep -v "> socket:\[" | grep -v "> pipe:\[" | grep -v "> anon_inode:" | grep -v "总用量 0" | grep -v "> net:\[" | grep -v "> mnt:\[" | grep -v "> /proc" | grep -v "> /dev/" | grep -v "> /run/"
const char *ignoreDirectory[] = {
    "/proc/",
    "/dev/",
    "/run/",
    "socket:[",
    "pipe:[",
    "anon_inode:",
    "net:[",
    "mnt:[",
};

int ignoreDir(const char* path)
{
    for(int i=0;i<sizeof(ignoreDirectory)/sizeof(ignoreDirectory[0]);++i)
    {
        if(strstr(path,ignoreDirectory[i]) == path)
            return 1;
    }
    return 0;
}

typedef struct _TMP_DATA
{
    int avi[6];
    long avl[6];
    char avc[6][MAX_PATH_LEN];
}TMP_DATA,*PTMP_DATA;
typedef struct
{
    long pid;
    long gpid;
    TRACE_POINT tp;
    ARGV_TYPE at[6];    // 每个变量的类型
    void *argvs[6];     // 每个变量的地址
    int argvsl[6];      // 每个变量的长度
} initCommonDataArgvs;
#define AUTO_PID    0,0
#define initCommonData(...) _initCommonData(&((initCommonDataArgvs){__VA_ARGS__}))
PCOMMON_DATA __initCommonData(initCommonDataArgvs *av)
{
    PCOMMON_DATA common_data = NULL;
    common_data = (PCOMMON_DATA)calloc(1,sizeof(COMMON_DATA));
    if(common_data)
    {
        common_data->tp = av->tp;
        common_data->pid = av->pid;
        common_data->gpid = av->gpid;
        for(int i=0,index=0;(i<sizeof(av->argvs)/sizeof(av->argvs[0])) && av->argvsl[i];++i)
        {
            if(index + av->argvsl[i] > sizeof(common_data->argvs)) break;
            memcpy(common_data->argvs+index,av->argvs[i],av->argvsl[i]);
            index += av->argvsl[i];
            common_data->at[i] = av->at[i];
            common_data->argvsl[i] = av->argvsl[i];
        }
    }
    return common_data;
}
PCOMMON_DATA _initCommonData(initCommonDataArgvs *av)
{
    if(!av->pid)
    {
        av->gpid = getpid();
        av->pid = gettid();
    }
    return __initCommonData(av);
}

int initPrefix(char *targetbuf, const int ofd)
{
    char *dirPath = NULL;
    size_t dirPathLen = 0;

    if(ofd != AT_FDCWD)
        getFdPath(&dirPath,&dirPathLen,ofd);
    else
        getCwd(&dirPath,&dirPathLen);

    strncat(targetbuf,dirPath,STR_USR_LEN);
    strncat(targetbuf,"/",STR_USR_LEN-strlen(targetbuf));
    return 0;
}

int getFdOpenFlag(pid_t gpid, pid_t pid, long fd)
{
    if(!real_open || !real_close) return -1;
    int ret = 0;
    char fdInfoPath[128] = { 0 };
    sprintf(fdInfoPath,"/proc/%u/task/%u/fdinfo/%ld",gpid,pid,fd);

    int mfd = real_open(fdInfoPath,O_RDONLY,0);
    do{
        if(mfd < 0 && errno == ENOENT)
        {
            memset(fdInfoPath,0,sizeof(fdInfoPath));
            // 进程目录的fdinfo和线程目录的fdinfo应该是一样的，故替换后再次尝试
            sprintf(fdInfoPath,"/proc/%u/fdinfo/%ld",gpid,fd);
            mfd = real_open(fdInfoPath,O_RDONLY,0);
        }
        if(mfd < 0) { ret = -2; break;}

        char buf[512]={0};
        read(mfd,buf,sizeof(buf)-1);
        char *flag_s = strstr(buf,"flags:\t"),
            *flag_e = NULL,*endptr = NULL;
        if(!flag_s) { ret = -3; break;}
        flag_s += strlen("flags:\t");
        flag_e = strstr(flag_s,"\n");
        if(!flag_e) { ret = -4; break;}
        flag_e[0] = '\0';

        ret = strtol(flag_s,&endptr,8);
        if(flag_s == endptr)
        { ret = -5; break;}
    }while(0);
    if(mfd>=0)   real_close(mfd);
    return ret;
}

PCOMMON_DATA initCloseMsg(const int __fd)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    char *path = NULL;
    size_t pathLen = 0;
    do
    {
        getFdPath(&path,&pathLen,__fd);
        if(!path)       break;
        common_data = initCommonData(AUTO_PID,ZyTracePointClose,
                                     {AT_BUF}, {path}, {pathLen});
        initsucc = 1;
    }while(0);
    if(path) free(path);
    return initsucc ? common_data : NULL;
}
PCOMMON_DATA initFexecveMsg(const int __fd)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    char *path = NULL;
    size_t pathLen = 0;
    do
    {
        getFdPath(&path,&pathLen,__fd);
        if(!path)       break;
        common_data = initCommonData(AUTO_PID,ZyTracePointExecve,
                                     {AT_BUF}, {path}, {pathLen});
        initsucc = 1;
    }while(0);
    if(path) free(path);
    return initsucc ? common_data : NULL;
}
PCOMMON_DATA initFmoduleMsg(const int __fd)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    char *path = NULL;
    size_t pathLen = 0;
    do
    {
        getFdPath(&path,&pathLen,__fd);
        if(!path)       break;
        common_data = initCommonData(AUTO_PID,ZyTracePointFinitModule,
                                     {AT_BUF}, {path}, {pathLen});
        initsucc = 1;
    }while(0);
    if(path) free(path);
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initModuleMsg(const char *path, int len)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    do
    {
        common_data = initCommonData(AUTO_PID,ZyTracePointInitModule,
                                     {AT_BUF}, {(void*)path}, {len});
        initsucc = 1;
    }while(0);
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initKillMsg(__pid_t *__pid, int *__sig)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    do
    {
        common_data = initCommonData(AUTO_PID,ZyTracePointKill,
                                     {AT_INT,AT_INT},
                                     {__pid,__sig},
                                     {sizeof(__pid_t),sizeof(int)});
        initsucc = 1;
    }while(0);
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initDeleteModuleMsg(const char *path, int len)
{
    int initsucc = 0;
    PCOMMON_DATA common_data = NULL;
    do
    {
        common_data = initCommonData(AUTO_PID,ZyTracePointDeleteModule,
                                     {AT_BUF}, {(void*)path}, {len});
        initsucc = 1;
    }while(0);
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initRenameMsg(const int __oldfd, const char *__old, const int __newfd,
                           const char *__new, TRACE_POINT tp)
{
    int initsucc = 0;
    PTMP_DATA tmp_data = NULL;
    PCOMMON_DATA common_data = NULL;
    if(__new && __old)
    {
        do
        {
            tmp_data = (PTMP_DATA)calloc(1,sizeof(TMP_DATA));
            if(!tmp_data)   break;
            if(__old[0] != '/') initPrefix(tmp_data->avc[0],__oldfd);
            if(__new[0] != '/') initPrefix(tmp_data->avc[1],__newfd);
            // 拼接前面处理好的路径
            strncat(tmp_data->avc[0],__old,sizeof(tmp_data->avc[0])-strlen(tmp_data->avc[0])-1);
            strncat(tmp_data->avc[1],__new,sizeof(tmp_data->avc[1])-strlen(tmp_data->avc[1])-1);
            realPath(tmp_data->avc[0],sizeof(tmp_data->avc[0]));
            realPath(tmp_data->avc[1],sizeof(tmp_data->avc[1]));
            common_data = initCommonData(AUTO_PID,tp,
                                         {AT_BUF,AT_BUF},
                                         {tmp_data->avc[0],tmp_data->avc[1]},
                                         {strlen(tmp_data->avc[0]),strlen(tmp_data->avc[1])});
            initsucc = 1;
        }while(0);
        if(tmp_data) free(tmp_data);
    }
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initOpenMsg(const int __fd, const char *__file, TRACE_POINT tp)
{
    int initsucc = 0;
    PTMP_DATA tmp_data = NULL;
    PCOMMON_DATA common_data = NULL;
    if(__file)
    {
        do
        {
            tmp_data = (PTMP_DATA)calloc(1,sizeof(TMP_DATA));
            if(!tmp_data)   break;
            if(__file[0] != '/') initPrefix(tmp_data->avc[0],__fd);
            // 拼接前面处理好的路径
            strncat(tmp_data->avc[0],__file,sizeof(tmp_data->avc[0])-strlen(tmp_data->avc[0])-1);
            realPath(tmp_data->avc[0],sizeof(tmp_data->avc[0]));
            common_data = initCommonData(AUTO_PID,tp,
                                         {AT_BUF},
                                         {tmp_data->avc[0]},
                                         {strlen(tmp_data->avc[0])});
            initsucc = 1;
        }while(0);
        if(tmp_data) free(tmp_data);
    }
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initUnlinkMsg(const int __fd, const char *__name, TRACE_POINT tp)
{
    int initsucc = 0;
    PTMP_DATA tmp_data = NULL;
    PCOMMON_DATA common_data = NULL;
    if(__name)
    {
        do
        {
            tmp_data = (PTMP_DATA)calloc(1,sizeof(TMP_DATA));
            if(!tmp_data)   break;
            if(__name[0] != '/') initPrefix(tmp_data->avc[0],__fd);
            // 拼接前面处理好的路径
            strncat(tmp_data->avc[0],__name,sizeof(tmp_data->avc[0])-strlen(tmp_data->avc[0])-1);
            realPath(tmp_data->avc[0],sizeof(tmp_data->avc[0]));
            common_data = initCommonData(AUTO_PID,tp,
                                         {AT_BUF},
                                         {tmp_data->avc[0]},
                                         {strlen(tmp_data->avc[0])});
            initsucc = 1;
        }while(0);
        if(tmp_data) free(tmp_data);
    }
    return initsucc ? common_data : NULL;
}

PCOMMON_DATA initExecveMsg(const int __fd, const char *__path, TRACE_POINT tp)
{
    int initsucc = 0;
    PTMP_DATA tmp_data = NULL;
    PCOMMON_DATA common_data = NULL;
    if(__path)
    {
        do
        {
            tmp_data = (PTMP_DATA)calloc(1,sizeof(TMP_DATA));
            if(!tmp_data)   break;
            if(__path[0] != '/') initPrefix(tmp_data->avc[0],__fd);
            // 拼接前面处理好的路径
            strncat(tmp_data->avc[0],__path,sizeof(tmp_data->avc[0])-strlen(tmp_data->avc[0])-1);
            realPath(tmp_data->avc[0],sizeof(tmp_data->avc[0]));
            common_data = initCommonData(AUTO_PID,tp,
                                         {AT_BUF},
                                         {tmp_data->avc[0]},
                                         {strlen(tmp_data->avc[0])});
            initsucc = 1;
        }while(0);
        if(tmp_data) free(tmp_data);
    }
    return initsucc ? common_data : NULL;
}
