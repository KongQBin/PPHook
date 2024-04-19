#pragma once
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "munistd.h"

extern int gLogFd;
int getCwd(char **cwd, size_t *len);
int getExe(char **exe, size_t *len);
int getFdPath(char **path, size_t *len, int fd);
void nhookputlog(const char *funcName,const char *msg);
