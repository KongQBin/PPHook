#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <queue>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include "../ZyThread.h"
using namespace std;
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

void printEnv()
{
    char *buffer = NULL;
    int bufsize = 0, readlen = 0;
    int fd = open("/proc/2190/environ",O_RDONLY);
    if(fd>=0)
    {
        while(1)
        {
            buffer = (char*)calloc(1,bufsize+256);
            if(!buffer) break;
            bufsize += 256;
            lseek(fd,0,SEEK_SET);
            readlen = read(fd,buffer,bufsize);
            if(readlen > 0 && readlen < bufsize) break;
            free(buffer);
            buffer = NULL;
            if(readlen < 0)
                break;
        }
        close(fd);
    }
    if(buffer)
    {
        for(int i=0;i<readlen;++i)
        {
            if(buffer[i]=='\0')
                printf("\n");
            else
                printf("%c",buffer[i]);
        }
        printf("\n");
        free(buffer);
    }
    //    ifstream examplefile("/proc/2190/environ");
    //    if (!examplefile.is_open())
    //    {cout << "Error   opening file"; exit (1);}
    //    while (!examplefile.eof()) {
    //        examplefile.getline(buffer,4095);
    //        cout << buffer<< endl;
    //    }
}

int testFree(int *a)
{
    if(a)
    {
        free(a);
        a = NULL;
    }
}




struct TestStruct
{
    int aa = 0;
    char bb[256] = { 0 };
};


int main(int argc, char **argv)
{
//    testRenameAt(argv[1],argv[2]);
//    testFork();
//    testFileCall();

    int *a = (int*)calloc(1,sizeof(int)*100);
    if(a) testFree(a);
    if(a) printf("a is not NULL\n");




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

//    FILE *fp = fopen("/home/kongbin/MyGit/SysMonApply/PPHook/testdm/b","a+");
//    if(!fp) printf("fopen err is %s(%d)\n",strerror(errno),errno);
//    int fd = open("/home/kongbin/MyGit/SysMonApply/PPHook/testdm/a",O_CREAT|O_RDWR,0777);
//    if(fd < 0) printf("open err is %s(%d)\n",strerror(errno),errno);
//    fcloseall();
//    int ret = write(fd,"1234\n",strlen("1234\n"));
//    if(ret != strlen("1234\n"))
//        printf("write err is %s(%d)\n",strerror(errno),errno);
//    ret = fputs("5678\n",fp);
//    if(!ret)
//        printf("fputs err is %s(%d)\n",strerror(errno),errno);
//    close(fd);
//    close(fd);

//    ZyMemPre<TestStruct> test;
//    test.setPreNum(100000,10000);
//    test.startPreMem();
//    for(int i=0;i<1000000000;++i)
//    {
////        if(i == 5000) test.stopPreMem();
////        usleep(0);
//        TestStruct *tmp = test.getStruct();
//        if(tmp)
//        {
//            memset(tmp,1,sizeof(TestStruct));
//            delete tmp;
//        }
//    }
//    printf("s1\n");
//    sleep(10);
//    printf("s2\n");


    return 0;
}
