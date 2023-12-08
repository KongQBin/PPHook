#include "hook1.h"

int main()
{
    int(*mclose)(int) = dlsym(REAL_LIBC, "close");
    if(mclose)  {printf("AAAAAAAAAAA\n");mclose(1);}
    return 0;

    char **names = NULL;
    void **funcs = NULL;
    int len = 0;
    gethooks(&names,&funcs,&len);
    printf("names = %x, funcs = %x\n",names,funcs);

    for(int i=0;i<len;++i)
    {
        printf("i = %d, name = %s, funcs = %x\n", i, names[i], funcs[i]);
    }

    return 0;
}
