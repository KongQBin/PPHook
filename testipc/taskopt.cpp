#include "taskopt.h"

void Semaphore::signal()
{
    unique_lock<mutex> unique(m_mtx);
    ++m_count;
    if (m_count <= 0)
        m_cond.notify_one();
}

void Semaphore::wait()
{
    unique_lock<mutex> unique(m_mtx);
    --m_count;
    if (m_count < 0)
        m_cond.wait(unique);
}

TaskOpt::TaskOpt()
{
}

TaskOpt::~TaskOpt()
{

}

int TaskOpt::init()
{
    int ret = 0;
    do{
        m_ipcSvr = getServer();
        if(!m_ipcSvr)
        {
            printf("getServer error\n");
            ret = -1;
            break;
        }
        if(m_ipcSvr->init(bind(&TaskOpt::MsgCallBack,this,placeholders::_1)))
        {
            printf("server init error\n");
            ret = -1;
            break;
        }
        m_answerThreadRun = true;
        ZyThread::autoRun(bind(&TaskOpt::answerThread,this));
    }while(0);
    return ret;
}

int TaskOpt::MsgCallBack(MonitorMsg *msg)
{
    MonitorMsg tmp;
    memcpy(&tmp,msg,sizeof(MonitorMsg));
    m_msgs.push(tmp);
    switch (tmp.type) {
    case M_FILE_MONITOR:
        printf("pid = %ld,\ttid = %ld,\tfunc = %s,\tpath1 = %s,\tpath2 = %s\n",
                   tmp.pid,tmp.tid,tmp.funcname,tmp.data.fmd.filepath,tmp.data.fmd.filepath2);
        break;
    case M_ACTIVE_DEFENSE:
        m_taskPV.signal();
        printf("pid = %ld,\ttid = %ld,\tfunc = %s,\texe = %s\n",tmp.pid,tmp.tid,tmp.funcname,tmp.data.add.exepath);
        break;
    case M_PROCESS_PROTECT:
        m_taskPV.signal();
        printf("pid = %ld,\ttid = %ld,\tfunc = %s,\tsignal = %d,\ttaegetexe = %s\n",
               tmp.pid,tmp.tid,tmp.funcname,tmp.data.ppd.signal,tmp.data.ppd.targetexe);
        break;
    default:
        break;
    }
    return 0;
}

void TaskOpt::answerThread()
{
    ControlMsg msg;
    while(m_answerThreadRun)
    {
        m_taskPV.wait();

        memset(&msg,0,sizeof(ControlMsg));
        msg.tid = m_msgs.front().tid;
        msg.dec = D_ALLOW;

        m_ipcSvr->answerMsg(&msg);
        m_msgs.pop();
    }
}

