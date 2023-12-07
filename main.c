#include "hook1.h"

int main()
{
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
