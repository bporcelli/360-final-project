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

#include <dirent.h>
#include "lwip_common.h"
#include <unistd.h>
#include <stdio.h>
#include "lwip_debug.h"
#include "lwip_level.h"
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/user.h>
#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/sysctl.h>

#include "lwip_utils.h"

#ifdef LWIP_OS_BSD
#include <libutil.h>
#endif

/*
#ifdef LWIP_OS_LINUX
int do_downgrade_fd(int fd) {
  fchown(fd, -1, LWIP_CF_UNTRUSTED_USERID);
  int rv = fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
  LWIP_CRITICAL("Downgrading using fchmod is %d, errno: %d", rv, errno);
  return 1;
}
#endif
*/

void closeAllOpenedHighIFiles() {

#ifdef LWIP_OS_BSD
        int mib[4];
        int error;
        size_t len;
        char *buf, *bp, *eb;
        struct kinfo_file *kf;


        len = 0;
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_FILEDESC;
        mib[3] = lwip_util_getpid();

        error = sysctl(mib, 4, NULL, &len, NULL, 0);
        if (error) {
                LWIP_INFO("Failed to open");
                return;
        }
        len = len * 4 / 3;
        buf = malloc(len);
        if (buf == NULL) {
                LWIP_INFO("Failed to open");
                return;
        }
        error = sysctl(mib, 4, buf, &len, NULL, 0);
        if (error) {
                LWIP_INFO("Failed to open");
                free(buf);
                return;
        }
        bp = buf;
        eb = buf + len;
        while (bp < eb) {
                kf = (struct kinfo_file *)(uintptr_t)bp;
                bp += kf->kf_structsize;

		if (!(kf->kf_flags & KF_FLAG_WRITE))
			continue;

		/* FreeBSD's pipe is bidirectional */
		if (kf->kf_type == KF_TYPE_PIPE)
			LWIP_CRITICAL("Pipe is opened. Need to close it...");

/*
		if (kf->kf_type != KF_TYPE_VNODE) {

			char *str;

                        switch (kf->kf_vnode_type) {
                        case KF_VTYPE_VREG:
                                str = "r";
                                break;

                        case KF_VTYPE_VDIR:
                                str = "d";
                                break;

                        case KF_VTYPE_VBLK:
                                str = "b";
                                break;

                        case KF_VTYPE_VCHR:
                                str = "c";
                                break;

                        case KF_VTYPE_VLNK:
                                str = "l";
                                break;

                        case KF_VTYPE_VSOCK:
                                str = "s";
                                break;

                        case KF_VTYPE_VFIFO:
                                str = "f";
                                break;

                        case KF_VTYPE_VBAD:
                                str = "x";
                                break;

                        case KF_VTYPE_VNON:
                        case KF_VTYPE_UNKNOWN:
                        default:
                                str = "?";
                                break;
                        }

			LWIP_CRITICAL("Special file (fd: %d) of type %s opened for writing, path is %s", kf->kf_fd, str, kf->kf_path);

                switch (kf->kf_type) {
                case KF_TYPE_VNODE:
                        str = "v";
                        break;

                case KF_TYPE_SOCKET:
                        str = "s";
                        break;

                case KF_TYPE_PIPE:
                        str = "p";
                        break;

                case KF_TYPE_FIFO:
                        str = "f";
                        break;

                case KF_TYPE_KQUEUE:
                        str = "k";
                        break;

                case KF_TYPE_CRYPTO:
                        str = "c";
                        break;

                case KF_TYPE_MQUEUE:
                        str = "m";
                        break;

                case KF_TYPE_SHM:
                        str = "h";
                        break;

                case KF_TYPE_PTS:
                        str = "t";
                        break;

                case KF_TYPE_SEM:
                        str = "e";
                        break;

                case KF_TYPE_NONE:
                case KF_TYPE_UNKNOWN:
                default:
                        str = "?";
                        break;
                }

			LWIP_CRITICAL("Its (fd: %d) KF_TYPE is %s.", kf->kf_fd, str);

	}
*/

		if (lwip_fd2Lv_write(kf->kf_fd) == LV_HIGH) {
			LWIP_CRITICAL("High integrity file (fd: %d) %s is opened with write flag set, will be closed.", kf->kf_fd, kf->kf_path);
			if (close(kf->kf_fd) < 0)
	 			LWIP_CRITICAL("Failed to close it. errno: %d", errno);

		}
	}
	free(buf);
#elif defined LWIP_OS_LINUX
  DIR *dirp;
  struct dirent *dp;
  char filePath[PATH_MAX]; //, linkPath[PATH_MAX];
  int fd, access_mode; //, len;

  dirp = opendir("/proc/self/fd");
  while (dirp){
    if ((dp = readdir(dirp)) != NULL) {

      if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
	continue;
      
      fd = atoi(dp->d_name);

      lwip_util_fd2fullPath(fd, filePath);
      access_mode = fcntl(fd, F_GETFL) & O_ACCMODE;
      if (access_mode & O_RDWR || access_mode & O_WRONLY) {
        if (lwip_level_isHigh(lwip_fd2Lv_write(fd)) || (strstr(filePath, "pipe:[") == filePath)) { //XXX: use fd2Lv_write???? A single file level is not sufficient!!!! e.g., /dev/pts
	  if (lwip_isDowngradableFile(filePath)) {
            LWIP_CRITICAL("File %s is downgradable...", filePath);
            lwip_util_downgradeFile_fd(fd);
	  }
          else
            LWIP_CRITICAL("File/Pipe %s is opened in write mode, but is not untrusted.", filePath);
            printf("High integrity file/pipe %s (%d) is opened in write mode, exec will not be continued\n", filePath, fd);
//		getchar();
            exit(-1);
            //sh_showUserMsgN("High integrity file %s is opened in write mode, exec will not be continued", filePath);
        }
      }

//      LWIP_CRITICAL("File checked: %s, mode: %d", filePath, access_mode);
/*
      snprintf(linkPath, PATH_MAX, "/proc/self/fd/%s", dp->d_name);
      len = readlink(linkPath, filePath, PATH_MAX);
      if (len <= 0 && errno != ENOENT) {
        LWIP_CRITICAL("Error in reading path %s", linkPath);
        continue;
      }
      filePath[len] = 0;
*/
    }
    else {
      closedir(dirp);
      break;
    }
  }
#endif
	return;
}





int main(int argc, char *argv[])
{
	char command[PATH_MAX];
	int i;
	int count = 0;
	/* char *env[] = {"DISPLAY=:0.0", NULL}; */

	int start_arg = 1;

	if (strcmp(argv[1], "--trusted") == 0)
		start_arg = 2;
	else
		closeAllOpenedHighIFiles();

	int rv = setresgid(LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID);
	if (rv < 0)
		perror("uudo failed to setresgid");


	rv = setresuid(LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID);
	if (rv < 0)
		perror("uudo failed to setresuid");


	

	for (i = start_arg; i < argc; i++) {
		count += snprintf(command + count, PATH_MAX - count, "\"%s\" ", argv[i]);
	}

	char *args[] = {"/bin/sh", "-c", command, NULL};


	//  setresuid(LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID, LWIP_CF_UNTRUSTED_USERID);

	execv("/bin/sh", args);
	/* execve("/bin/sh", args, env); */

	return 0;
}

