#ifndef WRAPPER_H
#define WRAPPER_H

#include <utime.h>      // struct utimbuf
#include <sys/statfs.h> // struct statfs
#include <sys/stat.h>   // struct stat
#include <fcntl.h>      // S_* constants
#include <dlfcn.h>      // dlsym and RTLD_NEXT

/* Ensure needed constants are defined */ 
#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif

/* Macro to help with wrapper definition */
#define sip_wrapper(type, name, ...) \
	type (*_ ##name)(__VA_ARGS__); \
	type name(__VA_ARGS__) \

#endif