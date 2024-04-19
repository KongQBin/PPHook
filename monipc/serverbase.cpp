#include "serverbase.h"
#include "ipcserver.h"
ServerBase *getServer()
{
    static IPCServer svr;
    return &svr;
}
