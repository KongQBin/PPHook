#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

int main(int argc, char **argv)
{
    testRenameAt(argv[1],argv[2]);
//    testFork();
    return 0;
}
