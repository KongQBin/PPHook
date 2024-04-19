#pragma once
#include <cstring>
#include <sys/epoll.h>
#include <algorithm>
#include <unistd.h>
#include <cstdlib>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <map>
#include "ZyThread.h"
#include "serverbase.h"
#include "ipcdef.h"
#include <sys/mman.h>
#define MAX_EVENTS 4096
typedef struct epoll_event epoll_event_t;
class IPCServer : public ServerBase
{
public:
    IPCServer();
    ~IPCServer();
    int init(CallBackFunc func);
    int unInit();
    int answerMsg(ControlMsg *msg);
    int setGlobalConfig(GlobalConfig *cfg);
private:
    int initSocket();
    int initMmap();
    void closeFds();
    void freeMems();
    void evtWaitThread();
    int m_socket;
    int m_epollfd;
    int m_threadRun;
    future<void> m_evtOptThread;
    CallBackFunc m_callBack;
    epoll_event_t m_event;
    epoll_event_t *m_events;
    MonitorMsg *m_msg;
    map<int,long> m_map;
    mutex m_mapMutex;
    GlobalConfig *m_config;
};
