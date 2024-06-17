#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../ZyThread.h"

void testRenameAt(char *p1, char *p2)
{
    DIR *dir = opendir("/tmp");
    if(dir)
    {
        int dfd = dirfd(dir);
        renameat(-100,p1,dfd,p2);
        closedir(dir);
    }
}



void testFileCall()
{
    FILE *fp_r = fopen("./123_r","r");
    if(!fp_r) printf("fp_r %s\n",strerror(errno));
    FILE *fp_w = fopen("./123_w","w+");
    if(!fp_w) printf("fp_w %s\n",strerror(errno));
    FILE *fp_a = fopen("./123_a","a+");
    if(!fp_a) printf("fp_a %s\n",strerror(errno));
    FILE *fp64_r = fopen64("./123_64_r","r");
    if(!fp64_r) printf("fp64_r %s\n",strerror(errno));
    FILE *fp64_w = fopen64("./123_64_w","w+");
    if(!fp64_w) printf("fp64_w %s\n",strerror(errno));
    FILE *fp64_a = fopen64("./123_64_a","a+");
    if(!fp64_a) printf("fp64_a %s\n",strerror(errno));

    FILE *re_fp_w = freopen("./123_re_r","r",stdin);
    if(!re_fp_w) printf("re_fp_w %s\n",strerror(errno));
    FILE *re_fp64_w = freopen64("./123_re_64_w","w",stdout);
    if(!re_fp64_w) printf("re_fp64_w %s\n",strerror(errno));


    if(fp_r) fclose(fp_r);
    if(fp_w) fclose(fp_w);
    if(fp_a) fclose(fp_a);
    fcloseall();
}

int getSysConfig(const char *path,long *num)
{
    FILE *fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%ld", num);
        fclose(fp);
    } else {
        *num = 0;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
//    testRenameAt(argv[1],argv[2]);
//    testFork();
//    testFileCall();

    // 获取最大读写缓冲区大小
//    long max_send_buf_size,max_recv_buf_size;
//    getSysConfig("/proc/sys/net/core/rmem_max",&max_recv_buf_size);
//    getSysConfig("/proc/sys/net/core/wmem_max",&max_send_buf_size);

//    printf("%ld,%ld\n",max_recv_buf_size,max_send_buf_size);


//    int ret = 0;
//    ret = mkdir("./123",0777);
//    printf("ret = %d err is %s(%d)\n",ret,strerror(errno),errno);
//    ret = mkdir("./123",0777);
//    printf("ret = %d err is %s(%d)\n",ret,strerror(errno),errno);

//    ZyThread::autoRun(testFileCall);
//    ZyThread::autoRun(testFileCall);
//    ZyThread::autoRun(testFileCall);

    FILE *fp = fopen("/home/user/MyGit/SysMonApply/PPHook/testdm/b","a+");
    if(!fp) printf("fopen err is %s(%d)\n",strerror(errno),errno);
    int fd = open("/home/user/MyGit/SysMonApply/PPHook/testdm/a",O_CREAT|O_RDWR,0777);
    if(fd < 0) printf("open err is %s(%d)\n",strerror(errno),errno);

    fcloseall();

    int ret = write(fd,"1234\n",strlen("1234\n"));
    if(ret != strlen("1234\n"))
        printf("write err is %s(%d)\n",strerror(errno),errno);
    ret = fputs("5678\n",fp);
    if(!ret)
        printf("fputs err is %s(%d)\n",strerror(errno),errno);

    close(fd);
    close(fd);
    return 0;
}
