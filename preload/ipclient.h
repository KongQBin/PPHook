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
int getOnoff(TRACE_POINT tp);
int getBackwait(TRACE_POINT tp);
void toInteractive(PCOMMON_DATA smsg,CONTROL_INFO *rmsg);
