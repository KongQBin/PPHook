#pragma once
#include <sys/un.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>
#include "define.h"
#include "structmsg.h"
#include "ipcdef.h"
#include "munistd.h"
int initIpc();
int unInitIpc();
int sendMsg(MonitorMsg *msg);
int recvMsg(ControlMsg *msg);
int getFileMonitor();
int getActiveDefense();
int getProcessProtect();
