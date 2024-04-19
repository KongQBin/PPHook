#include "taskopt.h"
#include <unistd.h>
int main(int argc, char **argv)
{
    TaskOpt taskOpt;
    taskOpt.init();
    while(1) sleep(1);
    return 0;
}
