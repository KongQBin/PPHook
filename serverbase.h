#pragma once
#include <functional>
#include "structmsg.h"
using namespace std;
typedef function<int(MonitorMsg*)> CallBackFunc;
class ServerBase
{
public:
    virtual int init(CallBackFunc func) = 0;
    virtual int unInit() = 0;
    virtual int answerMsg(ControlMsg *msg) = 0;
    virtual int setGlobalConfig(GlobalConfig *cfg) = 0;
};
class IPCServer;
#ifdef __cplusplus
extern "C" {
#endif
ServerBase* getServer();
#ifdef __cplusplus
}
#endif
