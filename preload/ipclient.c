#include "ipclient.h"
static int gClientSocket = -1;
static GlobalConfig *gConfig = NULL;
// 该函数不负责创建内存
int initMmap() {
    int ret = 0, fd = -1;
    do
    {
        if(gConfig)
            break;
        // 打开内存
        fd = shm_open(MMAP_PATH, O_RDWR, 0666);
        if(fd < 0)
        {
            ret = -1;
            break;
        }
        // 建立映射
        gConfig = mmap(NULL, sizeof(GlobalConfig), PROT_READ, MAP_SHARED, fd, 0);
        if(!gConfig)
        {
            ret = -2;
            break;
        }
    }while(0);
    if(fd >= 0 && real_close)
        real_close(fd);         // 切忌使用close，会造成死循环
    return ret;
}

int getFileMonitor()
{
    return gConfig ? gConfig->fileMonitor :
               (initMmap() ? 0 : gConfig->fileMonitor);
}
int getActiveDefense()
{
    return gConfig ? gConfig->activeDefense :
               (initMmap() ? 0 : gConfig->activeDefense);
}
int getProcessProtect()
{
    return gConfig ? gConfig->processProtect :
               (initMmap() ? 0 : gConfig->processProtect);
}

int unInitIpc()
{
    // 关闭套接字
    if(gClientSocket != -1)
    {
        real_close(gClientSocket);
        gClientSocket = -1;
    }
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
    int send_buffer_size = BUF_SIZE;
    if(setsockopt(gClientSocket, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == -1)
    {
        unInitIpc();
        return -2;
    }

    // 设置等待超时
    struct timeval tv_out;
    tv_out.tv_sec = 15;
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

    return 0;
}

int sendMsg(MonitorMsg *msg)
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
    msg->pid = getpid();
    msg->tid = gettid();
    // 发送消息
    if (send(gClientSocket, msg, sizeof(typeof(*msg)), 0) != sizeof(typeof(*msg)) <= 0){
        unInitIpc();
        return -2;
    }
    return 0;
}
int recvMsg(ControlMsg *msg)
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
    if(initIpc())
        return -1;
    memset(msg,0,sizeof(typeof(*msg)));
    // 接收回复
    int ret = recv(gClientSocket, msg, sizeof(typeof(*msg)),0);
    if(ret != sizeof(typeof(*msg))) {
        // 无论出现什么错误，此处都将消息标记为放行
        msg->dec = D_ALLOW;
        unInitIpc();
        return -2;
    }
    return 0;
}
