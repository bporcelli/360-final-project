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

#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>



#include <sys/stat.h>
#include <string.h>

#include "lwip_common.h"
#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_redirectHelper.h"
#include "lwip_bufferManager.h"

#ifdef LWIP_OS_LINUX
#include <sys/sendfile.h>
#endif
#include <stdio.h>

int lwip_copyFile_preservePermission(char *src, char *dst) {
	struct stat stat_buf;

	if (lwip_util_stat(src, &stat_buf)) {
		LWIP_ERROR("Failed to stat file %s, errno: %d", src, errno);
		return -1;
	}

	if (lwip_createDirsIgnLast_with_permissions_chmod(dst, -1, S_IRWXU, 1)) {
		LWIP_ERROR("Failed to create directories for destination: %s", dst);
		return -1;
	}

	return lwip_copyFile(src, dst, stat_buf.st_gid, stat_buf.st_mode);

}




int lwip_copyFileFD(int src, int dst) {
	off_t filesize;
	struct stat buf;

	lwip_util_fstat(src, &buf);
	filesize = buf.st_size;

	off_t total_byte_copied = 0, byte_copied;


#ifdef LWIP_OS_BSD
	void *buffer = lwip_bm_malloc(PATH_MAX);
	int byte_read;
	int rv = -1;

	while (total_byte_copied < filesize) {
		if ((byte_read = read(src, buffer, PATH_MAX)) > 0) {
			if ((byte_copied = write(dst, buffer, byte_read)) != byte_read) {
				LWIP_CRITICAL("Failed to use simple loop to copy: byte_copied != byte_read %lld vs %d", byte_copied, byte_read);
				break;
			}
			total_byte_copied += byte_copied;
			continue;
		} else if (byte_read == 0) {
			rv = 0;
			break;
		} else { /* byte_read < 0 */
			LWIP_CRITICAL("Failed to copy file: errno : %d", errno);
			break;
		}
	}
	lwip_bm_free(buffer);
	return rv;

#elif defined LWIP_OS_LINUX
	off_t offset = 0;

	while (total_byte_copied < filesize) {
		if ((byte_copied = sendfile(dst, src, &offset, filesize - total_byte_copied)) <= 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			LWIP_UNEXPECTED("Cannot copy file: %s, errno %d", lwip_util_nonSafefd2FullPath(src), errno);
			return -1;
		}
		total_byte_copied += byte_copied;
	}
	return 0;
#endif
}



int lwip_copyFile(char *src, char *dst, gid_t gid, mode_t mode) {
	struct stat stat_buf;
	char *directoryPath, *path2free;
	int rv;

	if (src[0] != '/') {
		LWIP_CRITICAL("Path must be absolute %s???", src);
	}

	if (access(src, R_OK)) {
		LWIP_CRITICAL("File cannot be read");
		return -1;
	}

	if (stat(src, &stat_buf)) {
		LWIP_CRITICAL("Cannot obtain file status %s, %d", src, errno);
		return -1;
	}

	if (S_ISDIR(stat_buf.st_mode)) {
		LWIP_CRITICAL("Object is a directory %s", src);
		return -1;
	}

	if (lwip_file2Lv_read(src) == LV_LOW)
		LWIP_CRITICAL("File to be redirected is of low integrity %s", src);

	
	if (lwip_util_stat(dst, &stat_buf)) {
		if (errno == ENOENT)
			goto do_copy_file;
		LWIP_CRITICAL("Error in stat the dst file %s, errno: %d", dst, errno);
		return -1;
	} else {
		LWIP_CRITICAL("destination file %s already exists", dst);
		return -1;
	}
	


do_copy_file:

	path2free = lwip_bm_malloc(PATH_MAX);
	strncpy(path2free, dst, PATH_MAX);
	directoryPath = dirname(path2free);
	if (lwip_util_stat(directoryPath, &stat_buf)) {
		LWIP_CRITICAL("Failed to stat the folder of the destination path: errno: %d", errno);
		rv = -1;
		goto free_directoryPath;
	}

	if (!S_ISDIR(stat_buf.st_mode)) {
		LWIP_CRITICAL("The destination directory path is not a directory");
		rv = -1;
		goto free_directoryPath;
	}

	int orgfile = open(src, O_RDONLY);
	if (orgfile == -1) {
		LWIP_CRITICAL("Failed to open original file for reading: %s, errno: %d", src, errno);
		rv = -1;
		goto free_directoryPath;
	}

	int newfile = open(dst, O_WRONLY|O_CREAT, S_IRWXU|S_IRWXG);
	if (newfile == -1) {
		LWIP_CRITICAL("Failed to create new file for %s, errno: %d", dst, errno);
		close(orgfile);
		rv = -1;
		goto free_directoryPath;
	}

	if (fchown(newfile, -1, gid)) {
		LWIP_CRITICAL("Failed to make dst %s group owned by %d, errno: %d", dst, gid, errno);
		rv = -1;
		goto free_directoryPath;
	}
	if (fchmod(newfile, mode)) {
		LWIP_CRITICAL("Failed to make dst %s of mode %s, errno: %d", dst, lwip_util_mode2perms(mode), errno);
		rv = -1;
		goto free_directoryPath;
	}

	if (lwip_copyFileFD(orgfile, newfile)) {
		LWIP_UNEXPECTED("Copying of file from %s to %s failed", src, dst);
		rv = -1;
		goto free_directoryPath;
	}

	LWIP_INFO("File copied %s -> %s", src, dst);
	rv = 0;

free_directoryPath:
	close(newfile);
	close(orgfile);
	lwip_bm_free(path2free);
	return rv;

}




int lwip_createDirs_with_permissions_chmod(char *dir, gid_t gid, mode_t mode, int performChmod) {
	char *tmpPath = lwip_bm_malloc(PATH_MAX);
	char *input = lwip_bm_malloc(PATH_MAX);
	char *partial, *next2print;

#ifdef LWIP_OS_LINUX
	struct stat64 buf;
#elif defined LWIP_OS_BSD
	struct stat buf;
#endif

	int rv = -1;


	if (dir == NULL || dir[0] != '/') {
		LWIP_CRITICAL("path is null or not absolute");
		goto out;
	}

	strncpy(input, dir+1, PATH_MAX-1);
	memset(tmpPath, 0, PATH_MAX);

	next2print = tmpPath;

	char *saved_ptr;
	partial = strtok_r(input, "/", &saved_ptr);
	do {


		*next2print = '/';
		next2print++;

		strncpy(next2print, partial, strnlen(partial, PATH_MAX));
		next2print += strnlen(partial, PATH_MAX);

		/* Calling stat will make some program result in segfault? */
		//LWIP_CRITICAL("In the loop %s, buf : %p", tmpPath, &buf);
#ifdef LWIP_OS_LINUX
		if (syscall(SYS_stat64, tmpPath, &buf) != 0) { // Calling stat will break for some programs
#elif defined LWIP_OS_BSD
		if (stat(tmpPath, &buf) != 0) {
#endif
//			LWIP_CRITICAL("Failed to stat %s errno: %d", tmpPath, errno);
			if (errno == ENOENT) {
				if (mkdir(tmpPath, mode)) {
					LWIP_CRITICAL("Failed to create directory %s", tmpPath);
					goto out;
				}
				if (gid != -1) {
					if (chown(tmpPath, -1, gid)) {
						LWIP_CRITICAL("Failed to make directory %s group owned by untrusted user", tmpPath);
					}
				}
				if (performChmod) {
					if (chmod(tmpPath, mode)) {
						LWIP_CRITICAL("Failed to make directory %s group writable by untrusted user", tmpPath);
					}
					LWIP_INFO("chmod is preformed");
				} else
					LWIP_INFO("chmod is not performed");

				LWIP_INFO("Directory created by delegator: %s", tmpPath);

				goto parse_next_token;
			}
			LWIP_ERROR("Failed to stat path %s during creating folders along %s", tmpPath, dir);
			goto out;
		}
		//LWIP_CRITICAL("In the loop BBB, rv %d", rv);
		if (!S_ISDIR(buf.st_mode)) {
			LWIP_CRITICAL("Failed to create directory as one path component %s is not directory", tmpPath);
			goto out;
		}
parse_next_token:
		partial = strtok_r(NULL, "/", &saved_ptr);

	} while (partial != NULL);

	rv = 0;
out:
	lwip_bm_free(tmpPath);
	lwip_bm_free(input);
		
	return rv;



}

int lwip_createDirsIgnLast_with_permissions_chmod(char *dir, gid_t gid, mode_t mode, int performChmod) {
	char *path2free = lwip_bm_malloc(PATH_MAX);
	strncpy(path2free, dir, PATH_MAX);
	char *dir2create = dirname(path2free);
	int rv = lwip_createDirs_with_permissions_chmod(dir2create, gid, mode, performChmod);
	if (rv < 0)
		LWIP_CRITICAL("Failed to create directory %s", dir2create);
	lwip_bm_free(path2free);
	return rv;
}


int lwip_moveFile_preservePermission(char *src, char *dst) {
	if (rename(src, dst)) {
		LWIP_CRITICAL("Failed to move the file : %d", errno);
		return -1;
	}
	return 0;
}

int lwip_moveFile(char *src, char *dst, gid_t gid, mode_t mode) {
	int rv = lwip_moveFile_preservePermission(src, dst);
	if (rv != 0)
		return rv;
	if (chown(dst, -1, gid)) {
		LWIP_CRITICAL("Failed to change the moved file %s ownership gid to %d, errno: %d", dst, gid, errno);
		return -1;
	}
	if (chmod(dst, mode)) {
		LWIP_CRITICAL("Failed to chmod for the file %s, errno: %d", dst, errno);
		return -1;
	}
	return 0;
}


