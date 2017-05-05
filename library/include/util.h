#ifndef UTIL_H
#define UTIL_H

#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

void logmsg(const char *format, ...);

#endif