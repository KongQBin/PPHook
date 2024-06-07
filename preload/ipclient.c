#include "ipclient.h"
static int gClientSocket = -1;
static CONTROL_INFO *gConfig = NULL;

// 创建内存映射虚拟文件
/*
 * shm_open的实现中又调用open函数！！
 * 一般情况下shm_open和open均存在于libc中，故会直接内部调用，不会再查找open符号。
 * 但在一些系统中，shm_open在librt库中，open函数在libc中，所以shm_open在调用时会再去查找open符号，
 * 当我们hook了open函数时，此处就会进入死循环 shm_open -> 我们的open -> initMmap -> shm_open。
 */
int mshm_open(const char *name, const int oflag, const int mode)
{

    char path[256] = {0};
    const char *shm = "/dev/shm/";
    if(strlen(shm)+strlen(name) > sizeof(path)-1)
        return -1;
    snprintf(path,sizeof(path)-1,"%s%s",shm,name);
    return real_open ? real_open(path,oflag,mode) : -1;
}
// 该函数不负责创建内存
int initMmap() {
    int ret = 0, fd = -1;
    do
    {
        if(gConfig)
            break;
        fd = mshm_open(MMAP_PATH, O_RDWR, 0666);
        if(fd < 0)
        {
            ret = -1;
            break;
        }
        // 建立映射
        gConfig = mmap(NULL, sizeof(CONTROL_INFO)*TP_MAX, PROT_READ, MAP_SHARED, fd, 0);
        if(!gConfig)
        {
            ret = -2;
            break;
        }
    }while(0);
    if(fd >= 0 && real_close)
        real_close(fd);         // 切忌直接使用close，会造成死循环
    return ret;
}

int getOnoff(TRACE_POINT tp)
{
    return tp>=TP_MAX ? 0 : (!initMmap() ? gConfig[tp].onoff[CF_ON_OFF] : 0);
}
int getBackwait(TRACE_POINT tp)
{
    return tp>=TP_MAX ? 0 : (!initMmap() ? gConfig[tp].onoff[CF_BACK_WAIT] : 0);
}

pthread_mutex_t rMutex;
int unInitIpc()
{
    // 关闭套接字
    if(gClientSocket != -1)
    {
        real_close(gClientSocket);
        gClientSocket = -1;
    }
    pthread_mutex_destroy(&rMutex);
//    // 顺便共享内存取消映射
//    munmap(gConfig, sizeof(GlobalConfig));
//    gConfig = NULL;
    return 0;
}
int initIpc() {

    // 判断是否需要初始化
    if(gClientSocket != -1)
        return 0;

    // 创建域套接字
    gClientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (gClientSocket == -1) {
        return -1;
    }

    // 设置缓冲区大小
    int send_buffer_size = 212992;
    if(setsockopt(gClientSocket, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == -1)
    {
        unInitIpc();
        return -2;
    }

    // 设置等待超时
    struct timeval tv_out;
    tv_out.tv_sec = 20;
    tv_out.tv_usec = 0;
    if(setsockopt(gClientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) == -1)
    {
        unInitIpc();
        return -3;
    }

    // 设置套接字地址并连接
    sockaddr_un_t address;
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);
    // 连接到服务器
    if (connect(gClientSocket, (sockaddr_t*)(&address), sizeof(address)) == -1) {
        unInitIpc();
        return -4;
    }
    pthread_mutex_init(&rMutex,NULL);
    return 0;
}

int sendMsg(PCOMMON_DATA msg)
{
    // EACCES：权限被拒绝，当前进程没有足够的权限执行发送操作。
    // EAGAIN 或 EWOULDBLOCK：套接字被标记为非阻塞，并且发送操作将阻塞。
    // EBADF：无效的文件描述符，套接字描述符无效或未打开。
    // ECONNRESET：连接被对方重置，通常表示远程端关闭了连接。
    // EFAULT：缓冲区指针指向无效的内存地址。
    // EINTR：发送操作被中断，通常是由于接收到信号而导致的中断。
    // EINVAL：无效的参数，如无效的套接字类型或无效的发送选项。
    // EMSGSIZE：消息太大，发送的数据超过了套接字的发送缓冲区大小限制。
    // ENOMEM：内存不足，无法分配足够的内存来执行发送操作。
    // ENOTCONN：套接字未连接，需要先建立连接后才能发送数据。
    // EPIPE：套接字处于断开状态，写入到已经关闭的套接字。
    if(initIpc())
        return -1;
    // 发送消息
    if (send(gClientSocket, msg, sizeof(COMMON_DATA), MSG_NOSIGNAL) != sizeof(COMMON_DATA)){
        //        printf("send :: %s(%d) gClientSocket = %d\n",strerror(errno),errno,gClientSocket);
        // 可能服务端退出了，尝试关闭重连，再发送
        unInitIpc();
        if(!initIpc())
        {
            if(send(gClientSocket, msg, sizeof(COMMON_DATA), MSG_NOSIGNAL) != sizeof(COMMON_DATA))
            {
                printf("send2 :: %s(%d) gClientSocket = %d\n",strerror(errno),errno,gClientSocket);
                return -3;
            }
        }
        else
            return -2;
    }
    return 0;
}
int recvMsg(CONTROL_INFO *msg)
{
    // EAGAIN 或 EWOULDBLOCK：套接字被标记为非阻塞，并且接收操作将阻塞。
    // EBADF：无效的文件描述符，套接字描述符无效或未打开。
    // ECONNRESET：连接被对方重置，通常表示远程端关闭了连接。
    // EFAULT：缓冲区指针指向无效的内存地址。
    // EINTR：接收操作被中断，通常是由于接收到信号而导致的中断。
    // EINVAL：无效的参数，如无效的套接字类型或无效的接收选项。
    // EMSGSIZE：接收缓冲区太小，无法容纳完整的接收数据。
    // ENOMEM：内存不足，无法分配足够的内存来执行接收操作。
    // ENOTCONN：套接字未连接，需要先建立连接后才能进行接收操作。
    // ETIMEDOUT：接收操作超时，未在指定的时间内接收到数据。
    int ret = 0;
    TRACE_POINT tp = msg->tp;
    do
    {
        if(initIpc())
        {
            ret = -1;
            break;
        }
        int forMaxNum = 50;
        while( --forMaxNum )
        {
            memset(msg,0,sizeof(typeof(*msg)));
            msg->dec = D_ALLOW;
            // 接收回复
            // MSG_PEEK 读取但不清空缓存 因为消息不一定是给自己的
            // 如此一来其它共用相同fd的、具有血缘关系的进程也会被唤醒
            int recvLen = recv(gClientSocket, msg, sizeof(typeof(*msg)),MSG_PEEK);
            if(recvLen != sizeof(typeof(*msg)))
            {
                ret = -2;
                break;
            }
            // 确定消息是给自己的，而不是其它具有血缘关系的进程的
            else if(msg->pid == gettid())
            {
                // 将消息从缓存中抹除
                recv(gClientSocket, msg, sizeof(typeof(*msg)),0);
                ret = 0;
                break;
            }
            // 开关策略有变更
            else if(msg->pid == 0)
            {
                // 判断当前追踪点的总开关是否被关闭
                // 判断当前追踪点的等待开关是否被关闭
                // 如果满足任意条件，则退出等待，立即返回
                if(!getOnoff(tp) || !getBackwait(tp))   break;
                else
                {
                    // 证明该消息对自己当前的行为没有影响
                    // 场景1：曾经对自身有影响，上次直接break了，
                    // 这次获取的消息只是上次遗留在缓存区的
                    // 场景2：消息确实不会影响自己
                    // 以上两种场景都需要将消息抹除掉，
                    // 由于是公共消息，抹除的话可能出现临界资源的问题
                    pthread_mutex_lock(&rMutex);
                    // 必须先利用非阻塞读取
                    recvLen = recv(gClientSocket, msg, sizeof(typeof(*msg)),MSG_PEEK|MSG_DONTWAIT);
                    if(recvLen == sizeof(typeof(*msg)) && msg->pid == 0)
                        recv(gClientSocket, msg, sizeof(typeof(*msg)),0);
                    pthread_mutex_unlock(&rMutex);
                    continue;
                }
            }
            else
            {
                sleep(0);
                // 如果获取了50次,都没有获取成功，则认为要接受消息的
                // 具有血缘关系的进程已经挂了，那么此处帮它把消息清除掉
                // 重新进入循环获取自己的消息
                if(!forMaxNum)
                {
                    recv(gClientSocket, msg, sizeof(typeof(*msg)),0);
                    forMaxNum = 50;
                }
            }
        }
    }while(0);
    // 等待过程出现错误，反初始化ipc
    if(ret) unInitIpc();
    return ret;
}
