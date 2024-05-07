#include "ipcserver.h"
class map_value_finder
{
public:
    map_value_finder(const long &id):m_id(id){}
    bool operator ()(const std::map<int, long>::value_type &pair)
    {
        printf("pair.secon = %d\tmid = %d\n",pair.second,m_id);
        return pair.second == m_id;
    }
private:
    const long &m_id;
};

IPCServer::IPCServer()
{
    m_socket = -1;
    m_epollfd = -1;
    m_threadRun = 0;
    m_callBack = nullptr;
    m_events = nullptr;
    m_msg = nullptr;
}

IPCServer::~IPCServer()
{
    unInit();
}

int IPCServer::init(CallBackFunc func)
{
    int ret = 0;
    do
    {
        // 确定回调可用
        if(!func)
        {
            ret = -1;
            break;
        }
        m_callBack = func;
        // 为最大监控事件开辟内存
        m_events = (epoll_event_t*)calloc(MAX_EVENTS,sizeof(epoll_event_t));
        if(!m_events)
        {
            perror("calloc m_events : ");
            ret = -2;
            break;
        }
        // 为消息开辟内存
        m_msg = (MonitorMsg*)calloc(1,sizeof(MonitorMsg));
        if(!m_msg)
        {
            perror("calloc m_msg : ");
            ret = -3;
            break;
        }
        // 初始化共享内存
        if(initMmap())
        {
            ret = -4;
            break;
        }
        // 初始化套接字连接
        if(initSocket())
        {
            ret = -5;
            break;
        }
        // 启动事件处理线程
        m_threadRun = 1;
        m_evtOptThread = ZyThread::run(bind(&IPCServer::evtWaitThread,this));
    }while(0);

    if(ret) unInit();
    return 0;
}

int IPCServer::unInit()
{
    closeFds();
    freeMems();
    if(access(SOCKET_PATH,F_OK) == 0)
        unlink(SOCKET_PATH);
    memset(m_config,0,sizeof(GlobalConfig));
    munmap(m_config,sizeof(GlobalConfig));
    return 0;
}

int IPCServer::answerMsg(ControlMsg *msg)
{
    int targetFd;
    int error = 0;

    m_mapMutex.lock();
    auto it = m_map.find(msg->tid);
    if(it == m_map.end())
        return -1;
    targetFd = it->second;
    m_mapMutex.unlock();

    if(!error)
    {
        // 回复消息
        if(send(targetFd, msg, sizeof(ControlMsg), MSG_NOSIGNAL) != sizeof(ControlMsg))
        {
            perror("send : ");
            error = -2;
        }
    }
    return error;
}

int IPCServer::setGlobalConfig(GlobalConfig *cfg)
{
    if(!cfg)        return -1;
    if(!m_config)   return -2;
    memcpy(m_config,cfg,sizeof(GlobalConfig));
    return 0;
}

void IPCServer::closeFds()
{
    if(m_epollfd != -1)
    {
        close(m_epollfd);
        m_epollfd = -1;
    }
    if(m_socket != -1)
    {
        close(m_socket);
        m_socket = -1;
    }
}

void IPCServer::freeMems()
{
    if(m_msg)
    {
        free(m_msg);
        m_msg = NULL;
    }
    if(m_events)
    {
        free(m_events);
        m_events = NULL;
    }
}

int IPCServer::initSocket()
{
    int ret = 0;
    do
    {
        if(access(SOCKET_PATH,F_OK) == 0)
            unlink(SOCKET_PATH);
        // 创建域套接字
        m_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if(m_socket == -1)
        {
            perror("socket : ");
            ret = -1;
            break;
        }
        // 设置套接字地址
        sockaddr_un_t address;
        address.sun_family = AF_UNIX;
        strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);
        // 绑定套接字
        if (bind(m_socket, (sockaddr_t*)(&address), sizeof(address)) == -1) {
            perror("bind : ");
            ret = -2;
            break;
        }
        // 监听套接字
        if (listen(m_socket, SOMAXCONN) == -1) {
            perror("listen : ");
            ret = -3;
            break;
        }
        // 创建 epoll 实例
        m_epollfd = epoll_create1(0);
        if (m_epollfd == -1) {
            perror("epoll_create : ");
            ret = -4;
            break;
        }
        // 添加服务端套接字到 epoll 实例中
        m_event.events = EPOLLIN;
        m_event.data.fd = m_socket;
        if (epoll_ctl(m_epollfd, EPOLL_CTL_ADD, m_socket, &m_event) == -1) {
            perror("epoll_ctl : ");
            ret = -4;
            break;
        }
    }while(0);
    if(ret) closeFds();
    return ret;
}

int IPCServer::initMmap()
{
    int ret = 0, fd = -1;
    do
    {
        if(m_config)
            break;
        // 创建内存
        fd = shm_open(MMAP_PATH, O_CREAT|O_RDWR, 0666);
        if(fd < 0)
        {
            ret = -1;
            break;
        }
        // 调整大小
        if(ftruncate(fd,sizeof(GlobalConfig)) < 0)
        {
            ret = -2;
            break;
        }
        // 建立映射
        m_config = (GlobalConfig*)mmap(NULL, sizeof(GlobalConfig), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if(!m_config)
        {
            ret = -3;
            break;
        }
        // 清空内存
        memset(m_config,0,sizeof(GlobalConfig));

    }while(0);
    if(fd >= 0)
    {
        close(fd);
        fd = -1;
    }
    return ret;
}

void IPCServer::evtWaitThread()
{
    if(!m_events) return;
    while(m_threadRun)
    {
        // 等待事件发生
        int num_events = epoll_wait(m_epollfd, m_events, MAX_EVENTS, -1);
        if (num_events == -1) {
            perror("epoll_wait : ");
            break;
        }
        // 处理事件
        for (int i = 0; i < num_events; ++i) {
            int fd = m_events[i].data.fd;
            // 新连接事件
            if (fd == m_socket) {
                int client_socket = accept(m_socket, NULL, NULL);
                if (client_socket == -1) {
                    perror("accept : ");
                    continue;
                }
                // 将客户端套接字添加到 epoll 实例中
                m_event.events = EPOLLIN;
                m_event.data.fd = client_socket;
                if (epoll_ctl(m_epollfd, EPOLL_CTL_ADD, client_socket, &m_event) == -1) {
                    perror("epoll_ctl : ");
                    close(client_socket);
                    continue;
                }
            }
            // 已连接套接字有数据可读事件
            else {
                memset(m_msg, 0, sizeof(MonitorMsg));
                ssize_t bytes_received = recv(fd, m_msg, sizeof(MonitorMsg), 0);
                if (bytes_received <= 0)
                {
                    if (bytes_received != 0)
                        printf("fd:%d\trecv err : %s(%d)\n",fd,strerror(errno),errno);
//                    else
//                        printf("fd:%d\tclient disconnected.\n",fd);
                    // 该fd断开或者出现了其它问题
                    m_mapMutex.lock();
                    // 清空使用相同fd的元素
                    for (auto it = m_map.begin(); it != m_map.end();) {
                        if (it->second == fd)
                            it = m_map.erase(it);
                        else
                            ++it;
                    }
                    m_mapMutex.unlock();
                    // 从 epoll 实例中移除套接字
                    epoll_ctl(m_epollfd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                    continue;
                }
                m_mapMutex.lock();
                // 更新映射关系
                printf(">>>>>> fd = %d\t",fd,m_msg->tid);
                m_map[m_msg->tid] = fd;
                m_mapMutex.unlock();
                // 将消息传递至上层
                m_callBack(m_msg);
            }
        }
    }
    return;
}
