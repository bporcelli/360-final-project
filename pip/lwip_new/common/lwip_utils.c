/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <errno.h>

#include "lwip_utils.h"
#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_notifier.h"
#include "lwip_bufferManager.h"

#include <sys/user.h>
#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/sysctl.h>

#include <dirent.h>


//Local buffer to store the current process image path
static char lwip_util_process_path_buf[PATH_MAX];



int lwip_util_strcmp(const char *dst, const char *src) {
	for (; *dst && *src; ++src, ++dst)
		if (*dst != *src)
			break;
	return *dst - *src;
}



#ifdef LWIP_OS_LINUX

pid_t lwip_util_gettid()
{
  return (pid_t)syscall(SYS_gettid);
}


char lwip_util_tmp_buf[PATH_MAX];
char *lwip_util_getProcessImagePath()
{
  char *path = lwip_util_process_path_buf;
  char *tempbuf = lwip_util_tmp_buf;
  snprintf(tempbuf, PATH_MAX, "/proc/%d/task/%d/exe", lwip_util_getpid(), lwip_util_gettid());
  memset(path, 0, PATH_MAX);
  readlink(tempbuf, path, PATH_MAX);
  return path;
}
#elif defined LWIP_OS_BSD
char *lwip_util_getProcessImagePath() {
  char *path = lwip_util_process_path_buf;
  int rv;
  memset(path, 0, PATH_MAX);
  /* FreeBSD specific */
  rv = readlink("/proc/curproc/file", path, PATH_MAX);
  if (rv <= 0)
    return NULL;
  return path;
}
#endif

/*
int lwip_util_cleanUpPath(char *inputStr, char *outputStr) {
	int i=0, j=0, lastIsSlash=0;
	while (inputStr[i] != '\0') {
		if (lastIsSlash && (inputStr[i] == '/')) {
			i++;
			continue;
		}

		lastIsSlash = (inputStr[i] == '/');	
		outputStr[j] = inputStr[i];
		i++; j++;
	}
	outputStr[j] = '\0';
	return 0;
}
*/



char *lwip_itoa(int val) {
	static char buf[32] = {0};

	if (val == 0)
		return "0";

	int i = 30;
	for (; val && i; --i, val /= 10)
		buf[i] = "0123456789"[val % 10];
	return &buf[i+1];
}



static char *lwip_util_nonSafefd2FullPath_buffer = NULL;
char *lwip_util_nonSafefd2FullPath(int fd) {
	if (lwip_util_nonSafefd2FullPath_buffer == NULL)
		lwip_util_nonSafefd2FullPath_buffer = lwip_bm_malloc(PATH_MAX);
	if (lwip_util_fd2fullPath(fd, lwip_util_nonSafefd2FullPath_buffer) >= 0)
		return lwip_util_nonSafefd2FullPath_buffer;
	else
		return NULL;
}




#ifdef LWIP_OS_LINUX
__thread char readPath[PATH_MAX];
int lwip_util_fd2fullPath(int fd, char *path)
{
  int len;
  int rv = 0;
  pid_t process_pid, thread_id;
//  char *readPath = malloc(PATH_MAX);

  process_pid = lwip_util_getpid();
  thread_id = lwip_util_gettid();

//  return -1;
//  snprintf(readPath, PATH_MAX, "/proc/%d/task/%d/fd/%d", process_pid, thread_id, fd);


	int count = 0;
	lwip_snprintf(readPath, PATH_MAX, &count, str, "/proc/", int, process_pid, str, "/task/", int, thread_id, str, "/fd/", int, fd);
	readPath[count] = 0;


/*  char *str;
  int count = 0;
  str = "/proc/";
  memcpy(readPath + count, str, strlen(str)); count += strlen(str);
  str = lwip_itoa(process_pid);
  memcpy(readPath + count, str, strlen(str)); count += strlen(str);
  str = "/task/";
  str = lwip_itoa(thread_id);
  memcpy(readPath + count, str, strlen(str)); count += strlen(str);
  str = "/fd/";
  str = lwip_itoa(fd);
  memcpy(readPath + count, str, strlen(str)); count += strlen(str);
  readPath[count] = 0;
*/  

  len = readlink(readPath, path, PATH_MAX);

  if (len <= 0) {
    if (errno != ENOENT)
      LWIP_ERROR("Error in readlink: %s: %d", readPath, errno);
    rv = -1;
    goto out;
  }
  path[len] = 0;
 out:
 // free(readPath);
  return rv;
}

#elif defined LWIP_OS_BSD

//__thread char readPath[PATH_MAX];
int lwip_util_fd2fullPath(int fd, char *path) {
	int rv = -1;
	/* FreeBSD specific */
	int mib[4];
	int error;
	size_t len;
	char *buf, *bp, *eb;
	struct kinfo_file *kf;

	path[0] = 0;

	len = 0;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FILEDESC;
	mib[3] = lwip_util_getpid();

	error = sysctl(mib, 4, NULL, &len, NULL, 0);
	if (error) {
		LWIP_INFO("Failed to open");
		return -1;
	}
	len = len * 4 / 3;
	buf = malloc(len);
	if (buf == NULL) {
		LWIP_INFO("Failed to open");
		return -1;
	}
	error = sysctl(mib, 4, buf, &len, NULL, 0);
	if (error) {
		LWIP_INFO("Failed to open");
		free(buf);
		return -1;
	}
	bp = buf;
	eb = buf + len;
	while (bp < eb) {
		kf = (struct kinfo_file *)(uintptr_t)bp;
		bp += kf->kf_structsize;
		if (kf->kf_fd == fd) {
			strncpy(path, kf->kf_path, PATH_MAX);
			rv = 0;
			break;
		}
	}
	if (rv == -1) {
		LWIP_ERROR("The fd %d is not opened", fd);
		path[0] = 0;
	}
	free(buf);
	return rv;
}
#endif

inline int lwip_util_stringInArray(const char *path, const char * const array[]) {
  int count = 0;

  if (path == NULL)
    return 0;

  while (array[count] != NULL) {
    if (strcmp(array[count], path) == 0) {
      return 1;
    } 
    count++;
  }
  return 0;
}


inline int lwip_util_stringInPrefixArray(const char *path, const char * const prefixArray[]) {
  int count = 0;
  while (prefixArray[count] != NULL) {
    if (strstr(path, prefixArray[count]) == path) {
      return 1;
    } 
    count++;
  }
  return 0;
}


inline int lwip_util_intInArray(int num, int array[]) {
  int count = 0;
  while (array[count] != -1) {
    if (array[count] == num)
      return 1;
    count++;
  }
  return 0;
}





ssize_t lwip_util_send_fd(int fd, void *ptr, size_t nbytes, int sendfd)
{
	struct msghdr msg;
	struct iovec iov[1];

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmptr;


	if (sendfd < 0) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

	} else {
		msg.msg_control = control_un.control;
		msg.msg_controllen = sizeof(control_un.control);

		cmptr = CMSG_FIRSTHDR(&msg);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		*((int *) CMSG_DATA(cmptr)) = sendfd;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	return (sendmsg(fd, &msg, 0));
}



ssize_t lwip_util_recv_fd(int fd, void *ptr, size_t nbytes, int *recvfd)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t n;

	union {
		struct cmsghdr cm;
		char     control[CMSG_SPACE(sizeof (int))];
	} control_un;
	struct cmsghdr  *cmptr;

	msg.msg_control  = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ( (n = recvmsg(fd, &msg, 0)) <= 0) {
		*recvfd = -1;
		LWIP_INFO("FD is not passed, err in receiving message: %d", errno);
		return n;
	}

	if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
			cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmptr->cmsg_level != SOL_SOCKET)
		{
			perror("control level != SOL_SOCKET");
			*recvfd = -1;
			LWIP_INFO("FD is not passed, return value is %d", *recvfd);
		}
		if (cmptr->cmsg_type != SCM_RIGHTS)
		{
			perror("control type != SCM_RIGHTS");
			*recvfd = -1;
			LWIP_INFO("FD is not passed, return value is %d", *recvfd);
		}
		*recvfd = *((int *) CMSG_DATA(cmptr));
	} else {
		int *rv = (int *)ptr;
		*recvfd = rv[2];           /* descriptor was not passed */
		LWIP_INFO("FD is not passed, return value is %d", *recvfd);
	}
	return n;
}




static __thread char lwip_util_perms_buff[20];
const char *lwip_util_mode2perms(mode_t mode)
{
  char ftype = '?';
  if (S_ISREG(mode)) ftype = '-';
  if (S_ISLNK(mode)) ftype = 'l';
  if (S_ISDIR(mode)) ftype = 'd';
  if (S_ISBLK(mode)) ftype = 'b';
  if (S_ISCHR(mode)) ftype = 'c';
  if (S_ISFIFO(mode)) ftype = '|';
  sprintf(lwip_util_perms_buff, "%c%c%c%c%c%c%c%c%c%c %c%c%c", 
	  ftype,
	  mode & S_IRUSR ? 'r' : '-',
	  mode & S_IWUSR ? 'w' : '-',
	  mode & S_IXUSR ? 'x' : '-',
	  mode & S_IRGRP ? 'r' : '-',
	  mode & S_IWGRP ? 'w' : '-',
	  mode & S_IXGRP ? 'x' : '-',
	  mode & S_IROTH ? 'r' : '-',
	  mode & S_IWOTH ? 'w' : '-',
	  mode & S_IXOTH ? 'x' : '-',
	  mode & S_ISUID ? 'U' : '-',
	  mode & S_ISGID ? 'G' : '-',
	  mode & S_ISVTX ? 'S' : '-');
  return (const char *)lwip_util_perms_buff;
}


int lwip_util_getFullPath(const char *orig, char *newpath) {
	char buf[PATH_MAX], rootdir[PATH_MAX];
	char workingdir[PATH_MAX], path[PATH_MAX];
	char *tok;

	memset(newpath, 0, PATH_MAX);
	memset(buf, 0, PATH_MAX);
	memset(workingdir, 0, PATH_MAX);
	memset(path, 0, PATH_MAX);
	memset(rootdir, 0, PATH_MAX);

	if (strcmp(orig, ".") == 0) {
		getcwd(newpath, PATH_MAX);
		return 1;
	}

	if (orig[0] == 0) {
		newpath[0] = 0;
		return 1;
	}



	// convert the original path into absolute path
	if (orig[0] != '/') {
		getcwd(workingdir, PATH_MAX);
		snprintf(buf, PATH_MAX, "%s/%s", workingdir, orig);
		strcat (workingdir, "/");
		strcat (workingdir, orig);
	}
	else {
		strncpy(newpath, orig, PATH_MAX);
		//read_link (newpath);
		return 1;
	}

	tok = strtok(buf, "/");
	do {
		memset(path, 0, PATH_MAX);
		if (0 == tok) break;
		if (strcmp(tok, ".") == 0)
			continue;
		if (strcmp(tok, "..") == 0) {
			int loc = strlen(newpath);
			while (newpath[loc] != '/' && loc >= 0)
				loc--;
			if (0 == loc)
				newpath[1] = 0;
			else
				newpath[loc] = 0;
			continue;
		}
		if (strcmp(newpath, "/") == 0) {
			strncpy(path, newpath, strlen(newpath));
			strcat(path, tok);
			if (access(path, F_OK) == 0)
				strcpy(newpath, path);
			else
				strncat(newpath, tok, PATH_MAX - strlen(newpath));
		}
		else {
			strncpy(path, newpath, strlen(newpath));
			strcat(path, "/");
			strcat(path, tok);
			if (access(path, F_OK) == 1)
				strcpy(newpath, path);
			else {
				strncat(newpath, "/", PATH_MAX - strlen(newpath));
				strncat(newpath, tok, PATH_MAX - strlen(newpath));
			}
		}

	}while ((tok = strtok(NULL, "/")) != 0);

	//This is required to prevent returning a null string.
	if (newpath[0] == 0)
		newpath[0] = '/';

	if( (strlen (rootdir)) && (strcmp(rootdir, "/") != 0) ) {
		snprintf(buf, PATH_MAX, "%s/%s", rootdir, newpath);
		strncpy(newpath, buf, PATH_MAX);
	}
	return 0;
}


int lwip_util_getFullPathAt(int dirfd, const char *path, char *dest) {

	int rv = -1;
        if (path == NULL) {
                if (lwip_util_fd2fullPath(dirfd, dest)) {
                        LWIP_CRITICAL("Failed to get dirfd path");
                        LWIP_CRITICAL("Cannot convert path to absolute: non cwd at: %s, %d", path, dirfd);
                        dest[0] = 0;
			goto out;
                }
        } else if (path[0] != '/') {
                if (dirfd != AT_FDCWD) {
                        if (lwip_util_fd2fullPath(dirfd, dest)) {
                                LWIP_CRITICAL("Failed to get dirfd path");
                                LWIP_CRITICAL("Cannot convert path to absolute: non cwd at: %s, %d", path, dirfd);
                                dest[0] = 0;
                                goto out;
                        }
                        int len = strlen(dest);
                        snprintf(dest+len, PATH_MAX-len, "/%s", path);
                } else
                        lwip_util_getFullPath(path, dest);
        } else
                strncpy(dest, path, PATH_MAX);
	rv = 0;
out:
	return rv;

}


/*
int lwip_util_closeAllLowIntegrityFile_read() {
	DIR *dirp;
	struct dirent *dp;
	char filePath[PATH_MAX];
	int fd, access_mode;
	int rv;

	dirp = opendir("/proc/self/fd");
	while (dirp){
		if ((dp = readdir(dirp)) != NULL) {

			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;
			fd = atoi(dp->d_name);
			if (lwip_util_fd2fullPath(fd, filePath))
				continue;
			access_mode = fcntl(fd, F_GETFL) & O_ACCMODE;
			if ((access_mode == O_RDWR) || (access_mode == O_RDONLY)) {
				if (lwip_level_isLow(lwip_fd2Lv_read(fd)) || (strstr(filePath, "pipe:[") == filePath)) { 
					//XXX: use fd2Lv_write???? A single file level is not sufficient!!!! e.g., /dev/pts
					LWIP_CRITICAL("Low integrity File/Pipe %s is opened in read.", filePath);
					rv = -1;
					closedir(dirp);
					goto out;
				}
			}
		}
		else {
			closedir(dirp);
			break;
		}
	}
	rv = 0;
out:
	return rv;
}
*/

/*
int lwip_util_isLastThread() {
	DIR *dirp;
	struct dirent *dp;
	int rv = 1, tid;
	char taskPath[100];

	return 0;
	LWIP_CRITICAL("checking if %d has more threads", getpid());
	snprintf(taskPath, 100, "/proc/%d/task", getpid());

	dirp = opendir(taskPath); //"/proc/self/task");
	while (dirp){
		if (((dp = readdir(dirp)) != NULL) || rv == 0) {

			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;
			tid = atoi(dp->d_name);

			LWIP_CRITICAL("Checking thread is %d", tid);

			if (tid == lwip_util_gettid())
				continue;

			rv = 0;
		}
		else {
			closedir(dirp);
			break;
		}
	}
	LWIP_CRITICAL("rv is %d", rv);
	return rv;


}
*/


/*
int lwip_util_downgrade_downgradableFiles() {
	DIR *dirp;
	struct dirent *dp;
	char filePath[PATH_MAX];
	int fd, access_mode;
	int rv;

	dirp = opendir("/proc/self/fd");
	while (dirp){
		if ((dp = readdir(dirp)) != NULL) {

			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;
			fd = atoi(dp->d_name);
			if (lwip_util_fd2fullPath(fd, filePath))
				continue;		

			access_mode = fcntl(fd, F_GETFL) & O_ACCMODE;
			if (((access_mode == O_RDWR) || (access_mode == O_WRONLY)) && lwip_isDowngradableFile(filePath))  {
			}
		}
		else {
			closedir(dirp);
			break;
		}
	}
	rv = 0;
//out:
	return rv;

}
*/

int __checkedInsideContainer = -1;

int lwip_util_isInsideContainer() {
	if (__checkedInsideContainer == -1) {
		char name[100];
		if (gethostname(name, sizeof(name))) {
			LWIP_CRITICAL("Failed to gethostname: errno: %d", errno);
			return 0;
		}

		if (strstr(name, "container") == name)
			__checkedInsideContainer = 1;
		else
			__checkedInsideContainer = 0;

	}
	return __checkedInsideContainer;
}

int lwip_util_isUserFileBuf(struct stat buf) {
	if (buf.st_uid != LWIP_CF_REAL_USERID && buf.st_uid != LWIP_CF_UNTRUSTED_USERID)
		return 0;
	if (buf.st_gid != LWIP_CF_REAL_USERID && buf.st_gid != LWIP_CF_UNTRUSTED_USERID)
		return 0;
	return 1;
}

int lwip_util_isUserFile(char *filePath) {
	struct stat buf;
	if (lwip_util_stat(filePath, &buf)) {
		LWIP_CRITICAL("Failed to stat the file: errno: %d", errno);
		return 0;
	}
	return lwip_util_isUserFileBuf(buf);
}

int lwip_util_isUserFile_fd(int fd) {
	struct stat buf;
	if (lwip_util_fstat(fd, &buf)) {
		LWIP_CRITICAL("Failed to stat the file: errno: %d", errno);
		return 0;
	}
	return lwip_util_isUserFileBuf(buf);
}


int lwip_util_downgradeFileAt(int dirfd, const char *filePath, int flag) {
	struct stat buf;
	if (lwip_util_fstatat(dirfd, filePath, &buf, flag)) {
		LWIP_UNEXPECTED("Attempt to downgrade a file which cannot be stat: %s, errno: %d", filePath, errno);
		return -1;
	}
	if (!lwip_util_isUserFileBuf(buf))
		return -1;

	if (fchownat(dirfd, filePath, -1, LWIP_CF_UNTRUSTED_USERID, flag))
		LWIP_UNEXPECTED("Cannot downgrade file chown: errno: %d", errno);

#ifdef LWIP_OS_LINUX
	flag = 0; /*Linux does not support fchmodat with flag != 0*/
#endif
	if (fchmodat(dirfd, filePath, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, flag))
		LWIP_UNEXPECTED("Cannot downgrade file chmod: errno: %d", errno);
	
	return 0;


}


int lwip_util_downgradeFile_fd(int fd) {
	struct stat buf;
	if (lwip_util_fstat(fd, &buf)) {
		LWIP_CRITICAL("Failed to stat the file: errno: %d", errno);
		return -1;
	}
	if (!lwip_util_isUserFileBuf(buf)) {
		LWIP_CRITICAL("Attempting to downgrade a non-user owned file");
		return -1;
	}

	if (buf.st_uid != buf.st_gid) {
		if ((buf.st_mode & S_IRWXO) != (buf.st_mode & S_IRWXG) >> 3) {
			LWIP_CRITICAL("Attempting to downgrade a file where group field is used");
			return -1;
		}
	}

	int original_other_permission = buf.st_mode & S_IRWXO;

	if (fchown(fd, -1, LWIP_CF_UNTRUSTED_USERID))
		LWIP_CRITICAL("Cannot downgrade file chown: errno: %d", errno);
	if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|original_other_permission))
		LWIP_CRITICAL("Cannot downgrade file chmod: errno: %d", errno);

	LWIP_INFO("Fd %d is downgraded", fd);

	return 0;


}


