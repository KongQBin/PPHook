#pragma once
#include <sys/un.h>
#include <sys/socket.h>
#define BUF_SIZE        16384
#define SOCKET_PATH     "/tmp/syshook.skt"
#define MMAP_PATH       "syshook.mmap"
typedef struct sockaddr_un sockaddr_un_t;
typedef struct sockaddr sockaddr_t;
