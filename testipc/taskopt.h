#include "serverbase.h"
#include "ZyThread.h"
#include <string.h>
#include <queue>
#include <mutex>
#include <condition_variable>
using namespace std;

class Semaphore
{
public:
    Semaphore(long count = 0)
        : m_count(count) {}
    //V操作，唤醒
    void signal();
    //P操作，阻塞
    void wait();

private:
    mutex m_mtx;
    condition_variable m_cond;
    long m_count;
};

class TaskOpt
{
public:
    TaskOpt();
    ~TaskOpt();
    int init();
private:
    int MsgCallBack(MonitorMsg *msg);
    void answerThread();
    bool m_answerThreadRun;
    Semaphore m_taskPV;
    ServerBase *m_ipcSvr;
    queue<MonitorMsg> m_msgs;
};
