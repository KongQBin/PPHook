#include "ipclient.h"
// __thread 利用TLS(Thread Local Storage)
// 机制，保证线程间不去共享这个变量
__thread int tGClientSocket = -1;
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
        if(--ret && fd < 0) break;
        // 建立映射
        gConfig = mmap(NULL, sizeof(CONTROL_INFO)*TP_MAX, PROT_READ, MAP_SHARED, fd, 0);
        if(--ret && !gConfig) break;
        ret = 0;
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

int unInitIpc()
{
    // 关闭套接字
    if(tGClientSocket != -1)
    {
        real_close(tGClientSocket);
        tGClientSocket = -1;
    }
//    // 顺便共享内存取消映射
//    munmap(gConfig, sizeof(GlobalConfig));
//    gConfig = NULL;
    return 0;
}


int getSysConfig(const char *path,long *num)
{
    void *fp = real_fopen(path, "r");
    if (fp) {
        fscanf(fp, "%ld", num);
        real_fclose(fp);
    } else {
        *num = 0;
        return -1;
    }
    return 0;
}
int initIpc()
{
    int ret = 0;
    do
    {
        // 判断是否需要初始化
        if(tGClientSocket != -1) break;
        // 创建域套接字
        tGClientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (--ret && tGClientSocket == -1) break;

        // 获取最大读写缓冲区大小
        long max_send_buf_size,max_recv_buf_size;
        if(--ret && getSysConfig("/proc/sys/net/core/rmem_max",&max_recv_buf_size)) break;
        if(--ret && getSysConfig("/proc/sys/net/core/wmem_max",&max_send_buf_size)) break;

        // 设置缓冲区大小
        if(--ret && setsockopt(tGClientSocket, SOL_SOCKET, SO_RCVBUF,
                       &max_recv_buf_size, sizeof(max_recv_buf_size)) == -1) break;
        if(--ret && setsockopt(tGClientSocket, SOL_SOCKET, SO_SNDBUF,
                       &max_send_buf_size, sizeof(max_send_buf_size)) == -1) break;

        // 设置等待超时
        struct timeval tv_out;
        tv_out.tv_sec = 20;
        tv_out.tv_usec = 0;
        if(--ret && setsockopt(tGClientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) == -1) break;

        // 设置套接字地址并连接
        sockaddr_un_t address;
        address.sun_family = AF_UNIX;
        strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);
        // 连接到服务器
        if (--ret && connect(tGClientSocket, (sockaddr_t*)(&address), sizeof(address)) == -1) break;
        ret = 0;
    }while(0);
    if(ret < -1)
    {
        real_close(tGClientSocket);
        tGClientSocket = -1;
    }
    return ret;
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
    if(initIpc()) return -1;
    // 发送消息
    if (send(tGClientSocket, msg, sizeof(COMMON_DATA), MSG_NOSIGNAL) != sizeof(COMMON_DATA)){
        //        printf("send :: %s(%d) tGClientSocket = %d\n",strerror(errno),errno,tGClientSocket);
        // 可能服务端退出了，尝试关闭重连，再发送
        unInitIpc();
        if(!initIpc())
        {
            if(send(tGClientSocket, msg, sizeof(COMMON_DATA), MSG_NOSIGNAL) != sizeof(COMMON_DATA))
            {
                printf("send2 :: %s(%d) tGClientSocket = %d\n",strerror(errno),errno,tGClientSocket);
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
        memset(msg,0,sizeof(CONTROL_INFO));
        msg->dec = D_ALLOW;
        // 接收回复
        int recvLen = recv(tGClientSocket, msg, sizeof(CONTROL_INFO),0);
        if(recvLen != sizeof(CONTROL_INFO))
        {
            ret = -2;
            break;
        }
        // 确定消息是给自己的
        else if(msg->pid == mgettid())
            break;
        // 开关策略有变更
        else if(msg->pid == 0)
        {
            // 判断当前决定阻塞的开关是否被关闭
            // 如果满足任意条件，则退出等待，立即返回
            if(!getOnoff(tp) || !getBackwait(tp))   break;
            else continue;
        }
        else
        {
            // 发送端代码逻辑正常的话，不应该进入到这里
            break;
        }
    }while(0);
    // 等待过程出现错误，反初始化ipc
    if(ret) unInitIpc();
    return ret;
}
