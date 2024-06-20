#pragma once
#include <sys/un.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "define.h"
//#include "structmsg.h"
#include "ipcdef.h"
#include "munistd.h"
#include "com.h"
int initIpc();
int unInitIpc();
int sendMsg(PCOMMON_DATA msg);
int recvMsg(CONTROL_INFO *msg);
int getOnoff(TRACE_POINT tp);
int getBackwait(TRACE_POINT tp);
