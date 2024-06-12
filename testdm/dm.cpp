#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

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
    sleep(5);
    FILE *fp_r = fopen("./123_r","r");
    if(!fp_r) printf("fp_r %s\n",strerror(errno));
    sleep(1);
    FILE *fp_w = fopen("./123_w","w+");
    if(!fp_w) printf("fp_w %s\n",strerror(errno));
    sleep(1);
    FILE *fp_a = fopen("./123_a","a+");
    if(!fp_a) printf("fp_a %s\n",strerror(errno));
    sleep(1);
    FILE *fp64_r = fopen64("./123_64_r","r");
    if(!fp64_r) printf("fp64_r %s\n",strerror(errno));
    sleep(1);
    FILE *fp64_w = fopen64("./123_64_w","w+");
    if(!fp64_w) printf("fp64_w %s\n",strerror(errno));
    sleep(1);
    FILE *fp64_a = fopen64("./123_64_a","a+");
    if(!fp64_a) printf("fp64_a %s\n",strerror(errno));
    sleep(1);

    FILE *re_fp_w = freopen("./123_re_r","r",stdin);
    if(!re_fp_w) printf("re_fp_w %s\n",strerror(errno));
    sleep(1);
    FILE *re_fp64_w = freopen64("./123_re_64_w","w",stdout);
    if(!re_fp64_w) printf("re_fp64_w %s\n",strerror(errno));
    sleep(1);


    if(fp_r) fclose(fp_r);
    sleep(1);
    if(fp_w) fclose(fp_w);
    sleep(1);
    if(fp_a) fclose(fp_a);
    sleep(1);
    fcloseall();
    sleep(1);
}

int main(int argc, char **argv)
{
//    testRenameAt(argv[1],argv[2]);
//    testFork();
    testFileCall();
    return 0;
}
