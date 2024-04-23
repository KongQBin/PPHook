#pragma once

typedef enum _MonitorType
{
    M_FILE_MONITOR,
    M_ACTIVE_DEFENSE,
    M_PROCESS_PROTECT,
} MonitorType;
typedef struct _FileMonitorData
{
    char filepath[4096];    // 文件修改时仅有这个
    char filepath2[4096];   // 文件rename时，此为newpath
} FileMonitorData;
typedef struct _ActiveDefenseData
{
    char filepath[4096];     // 可执行文件路径
} ActiveDefenseData;
typedef struct _ProcessProtectData
{
    int signal;             // 信号
    char targetexe[4096];   // 发往哪个进程
} ProcessProtectData;
typedef union _MonitorData
{
    FileMonitorData fmd;
    ActiveDefenseData add;
    ProcessProtectData ppd;
} MonitorData;
// 来自底层的消息
typedef struct _MonitorMsg
{
    long tid;               // 任务来源(线程id)(交互Key)
    long pid;               // 任务来源(进程id)
    char funcname[32];      // 源自哪个系统调用
    MonitorType type;       // 任务类型
    MonitorData data;       // 任务数据
} MonitorMsg;

// 全局配置(想了想还是扔在共享内存吧)
// 这不像在内核中，维持了一份全局数据，
// 在当前这种模式下，每个进程都有一份GlobalConfig
// 其1：难以逐一通知每个进程，因为当前模式并没有一个长期等待消息的线程
// 其2：若单独为其启动一个线程来等待所有消息，即损失性能，又会涉及到同步的问题，
// 因为单个进程中可能存在多个线程在阻塞，等待消息的线程要判断将消息发给哪个阻塞中的线程
// 其3：若单独为其启动一个线程仅用来等待全局消息，即损失性能，又得单独为阻塞任务建立通信
// 其4：若进程在进行每一项操作前通过socket去拉取数据，可能会造成性能开支过大
typedef struct _GlobalConfig
{
    int fileMonitor;        // 文件监控
    int activeDefense;      // 主动防御
    int processProtect;     // 进程保护
} GlobalConfig;

typedef enum _Decision
{
    D_ALLOW,                // 放行该调用
    D_DENIAL,               // 拒绝该调用
} Decision;
// 发向底层的消息
typedef struct _ControlMsg
{
    long tid;               // 任务来源（务必与MonitorMsg一致）
    Decision dec;
} ControlMsg;
