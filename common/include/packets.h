#ifndef _SIP_PKT_H
#define _SIP_PKT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <limits.h>
#include <utime.h>

#define SIP_DATA_SZ 75
#define SYS_fstatat SYS_fstatat64
#define SYS_delegatortest 400
#define SYS_statvfs 401

#define SIP_PREPARE_RES(varname) struct sip_response varname

/* example use: SIP_PREPARE_PKT(openat, request); */
#define SIP_PREPARE_REQ(name, vname) 						\
	struct sip_request_ ##name vname = { 					\
		.head.size = sizeof(struct sip_request_ ##name), 	\
		.head.callno = SYS_ ##name							\
	}														\

struct sip_header {
	int callno; 			/* syscall number */
	int size; 				/* packet size, in bytes */
};

struct sip_response {
	int rv;    			   	/* return value */
	int err; 			   	/* error number (0 if successful) */
	char buf[SIP_DATA_SZ]; 	/* buffer for extra data */
};

/* test syscall */
struct sip_request_test {
	struct sip_header head;
	int err;
};

/* faccessat */
struct sip_request_faccessat {
	struct sip_header head;
	char pathname[PATH_MAX];
	int mode;
	int flags;
};

/* fchmodat */
struct sip_request_fchmodat {
	struct sip_header head;
	char pathname[PATH_MAX];
	mode_t mode;
	int flags;
};

/* fchownat */
struct sip_request_fchownat {
	struct sip_header head;
	char pathname[PATH_MAX];
	uid_t owner;
	gid_t group;
	int flags;
};

/* fstatat */
struct sip_request_fstatat {
	struct sip_header head;
	char pathname[PATH_MAX];
	int flags;
};

/* statvfs */
struct sip_request_statvfs {
	struct sip_header head;
	char path[PATH_MAX];
};

/* linkat */
struct sip_request_linkat {
	struct sip_header head;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	int flags;
};

/* mkdirat */
struct sip_request_mkdirat {
	struct sip_header head;
	char pathname[PATH_MAX];
	mode_t mode;
};

/* mknodat */
struct sip_request_mknodat {
	struct sip_header head;
	char pathname[PATH_MAX];
	mode_t mode;
	dev_t dev;
};

/* openat */
struct sip_request_openat {
	struct sip_header head;
	char file[PATH_MAX];
	int flags;
	mode_t mode;
};

/* renameat2 */
struct sip_request_renameat2 {
	struct sip_header head;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	unsigned int flags;
};

/* symlinkat */
struct sip_request_symlinkat {
	struct sip_header head;
	char target[PATH_MAX];
	char linkpath[PATH_MAX];
};

/* unlinkat */
struct sip_request_unlinkat {
	struct sip_header head;
	char pathname[PATH_MAX];
	int flags;
};

/* utime */
struct sip_request_utime {
	struct sip_header head;
	char path[PATH_MAX];
	struct utimbuf times;
};

/* utimes */
struct sip_request_utimes {
	struct sip_header head;
	char filename[PATH_MAX];
	struct timeval times[2];
};

/* utimensat */
struct sip_request_utimensat {
	struct sip_header head;
	char pathname[PATH_MAX];
	struct timespec times[2];
	int flags;
};

/* bind */
struct sip_request_bind {
	struct sip_header head;
	struct sockaddr addr;
	int socktype;			/* needed for server side socket(2) call. */
	socklen_t addrlen;
};

/* connect */
struct sip_request_connect {
	struct sip_header head;
	struct sockaddr addr;
	int socktype;			/* needed for server side socket(2) call. */
	socklen_t addrlen;
};

#endif
