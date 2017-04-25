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

#include "lwip_debug.h"
#include "lwip_common.h"
#include "lwip_level.h"
#include "lwip_utils.h"

#include "lwip_redirect.h"
#include "lwip_syscall_handler.h"
#include "lwip_redirectHelper.h"
#include "lwip_bufferManager.h"
#include "lwip_delegator_connection.h"

#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

static __thread char buffer_path1[PATH_MAX];
static __thread char buffer_path2[PATH_MAX];


void convert2FullPath(unsigned int *reg)
{
  char *org = (char *)*reg;
  
  if (org == NULL)
    return;
  
  if (org[0] != '/') {
    memset(buffer_path1, 0, sizeof(buffer_path1));
    lwip_util_getFullPath(org, buffer_path1);
    *reg = (unsigned int) buffer_path1;
  }

}


void convert2FullAndRedirectPath(unsigned int *reg)
{
  char *org = (char *)*reg;
  char *fullpath = org;
  
  if (org == NULL)
    return;
  
  if (org[0] != '/') {
    memset(buffer_path1, 0, sizeof(buffer_path1));
    lwip_util_getFullPath(org, buffer_path1);
    fullpath = buffer_path1;
    *reg = (unsigned int) buffer_path1;
  }

/*
  if (strstr(org, "//") != NULL) {
    if (realpath(org, buffer_path1)) {
      LWIP_CRITICAL("Failed to get realpath for %s: errno: %d", org, errno);
      return;
    }
    *reg = (unsigned int) buffer_path1;
    fullpath = buffer_path1;
  }
*/

	//No redirection when in iso mode.
	if (lwip_isISO_mode && lwip_util_isInsideContainer())
		return;

	if (lwip_isIN_mode)
		return;


  if (sh_processLevel == LV_LOW) {

    snprintf(buffer_path2, PATH_MAX, LWIP_REDIRECTION_PATH "%s", fullpath);
    if (lwip_isRedirectableFile(fullpath) && lwip_util_fileExist(buffer_path2)){
//      LWIP_INFO("Path is redirectable and file %s is redirected", fullpath);
      *reg = (unsigned int) buffer_path2;
    }
    else if (lwip_isRedirectableFile(fullpath) && (errno = 1, !(lwip_util_fileExist(fullpath)))) {
	//should contact the delegator to check if the file exists, if permission error!!
	if (errno == ENOENT)
		*reg = (unsigned int) buffer_path2;
//      do_redirection1(reg);
	//TODO: Simply return the corresponding redirected path, without creating directory!
	//Let the delegator decides what to do....
//      LWIP_INFO("Path is redirectable but file %s does not exist, doing redirection", buffer_path2);
    }
/*    else {
      LWIP_INFO("Path is not redirectable %s", fullpath);
    }*/
  }
  return;
}


void convert2FullAndRedirectPath_re(unsigned int *reg, char buffer[PATH_MAX]) {
  char *org = (char *)*reg;
  char *fullpath = org;
  
  if (org == NULL)
    return;
  
  if (org[0] != '/') {
    memset(buffer, 0, sizeof(buffer));
    lwip_util_getFullPath(org, buffer);
    fullpath = buffer;
    *reg = (unsigned int) buffer;
  }

  //No redirection when in iso mode.
  if (lwip_isISO_mode && lwip_util_isInsideContainer())
	  return;

  if (lwip_isIN_mode)
	  return;


  if (LWIP_PROCESS_LV_LOW) {
	char *tempBuffer = lwip_bm_malloc(PATH_MAX);
	snprintf(tempBuffer, PATH_MAX, LWIP_REDIRECTION_PATH "%s", fullpath);
	if (lwip_isRedirectableFile(fullpath) && lwip_util_fileExist(tempBuffer)){
		//LWIP_INFO("Path is redirectable and file %s is redirected", fullpath);
		memcpy(buffer, tempBuffer, PATH_MAX);
	}
	else if (lwip_isRedirectableFile(fullpath) && (errno = 1, !(lwip_util_fileExist(fullpath)))) {
		//should contact the delegator to check if the file exists, if permission error!!
		if (errno == ENOENT)
			memcpy(buffer, tempBuffer, PATH_MAX);
			//*reg = (unsigned int) buffer_path2;
		//      do_redirection1(reg);
		//TODO: Simply return the corresponding redirected path, without creating directory!
		//Let the delegator decides what to do....
		//      LWIP_INFO("Path is redirectable but file %s does not exist, doing redirection", buffer_path2);
	}
	/*    else {
	      LWIP_INFO("Path is not redirectable %s", fullpath);
	      }*/
	lwip_bm_free(tempBuffer);
  }
  return;

}



/* force = 1: convert to full and redirected path regardless of whether file exists */
void convert2FullAndRedirectPathat_re_force(unsigned int *dirfd, unsigned int *reg, char *buffer1, char *buffer2, int force){
	char *org = (char *)*reg;
	if (org == NULL)
		goto out;

	int dirfd1 = (int)*dirfd;

	if (org[0] != '/') {
		if (dirfd1 != AT_FDCWD) {
			if (lwip_util_fd2fullPath(dirfd1, buffer1)) {
				LWIP_CRITICAL("Failed to get dirfd path");
				LWIP_CRITICAL("Cannot convert path to absolute: non cwd at: %s, %d", org, dirfd1);
				goto out;
			}
			int len = strlen(buffer1);
			snprintf(buffer1+len, PATH_MAX-len, "/%s", org);
		} else
			lwip_util_getFullPath(org, buffer1);
	} else {

/*		if (strstr(org, "//") != NULL) {
			if (realpath(org, buffer1)) {
				LWIP_CRITICAL("Failed to get realpath for %s: errno: %d", org, errno);
				goto out;
			}
		} else
*/			strncpy(buffer1, org, PATH_MAX);
	}

	*reg = (unsigned int) buffer1;
	*dirfd = -1;

	//No redirection when in iso mode.
	if (lwip_isISO_mode && lwip_util_isInsideContainer())
		return;

	if (lwip_isIN_mode)
		return;

	if (sh_processLevel == LV_LOW) {
		char *fullpath = buffer1;
		snprintf(buffer2, PATH_MAX, LWIP_REDIRECTION_PATH "%s", fullpath);
		if (lwip_isRedirectableFile(fullpath) && (force || lwip_util_fileExist(buffer2))){
			//      LWIP_INFO("Path is redirectable and file %s is redirected", fullpath);
			*reg = (unsigned int) buffer2;
		}
		else if (lwip_isRedirectableFile(fullpath) && (errno = 0, !(lwip_util_fileExist(fullpath)))) {
		//should contact the delegator to check if the file exists, if permission error!!
			if (errno == ENOENT)
				*reg = (unsigned int) buffer2;
		}
		else {
//		      LWIP_INFO("TEMP REDIRECT Path is not redirectable %s", fullpath);
		}
	}

//	LWIP_INFO("TEMP REDIRECT final_name: %s", (char *)*reg);

out:

//	LWIP_INFO("TEMP REDIRECT out");
	return;
}

char *getFullandRedirectedPath(int dirfd, char *path, char *resultBuffer) {

	char *result = NULL;
	char *tempBuffer = NULL;

	if (path == NULL) {
		if (lwip_util_fd2fullPath(dirfd, resultBuffer)) {
			LWIP_CRITICAL("Failed to get dirfd path");
			LWIP_CRITICAL("Cannot convert path to absolute: non cwd at: %s, %d", path, dirfd);
			resultBuffer[0] = 0;
			goto out;
		}
		result = resultBuffer;
		goto out;
	}

	if (path[0] != '/') {
		if (dirfd != AT_FDCWD) {
			if (lwip_util_fd2fullPath(dirfd, resultBuffer)) {
				LWIP_CRITICAL("Failed to get dirfd path");
				LWIP_CRITICAL("Cannot convert path to absolute: non cwd at: %s, %d", path, dirfd);
				resultBuffer[0] = 0;
				goto out;
			}
			int len = strlen(resultBuffer);
			snprintf(resultBuffer+len, PATH_MAX-len, "/%s", path);
		} else
			lwip_util_getFullPath(path, resultBuffer);
	} else
		strncpy(resultBuffer, path, PATH_MAX);
	result = resultBuffer;

	//No redirection when in iso mode.
	if (lwip_isISO_mode && lwip_util_isInsideContainer())
		goto out;

	if (lwip_isIN_mode)
		goto out;

	if (sh_processLevel == LV_LOW) {
		char *fullpath = resultBuffer;
		tempBuffer = lwip_bm_malloc(PATH_MAX);
		snprintf(tempBuffer, PATH_MAX, LWIP_REDIRECTION_PATH "%s", fullpath);

		if (lwip_isRedirectableFile(fullpath) && lwip_util_fileExist(tempBuffer)){
			strcpy(resultBuffer, tempBuffer);
		}
		else if (lwip_isRedirectableFile(fullpath) && (errno = 0, !(lwip_util_fileExist(fullpath)))) {
		//should contact the delegator to check if the file exists, if permission error!!
			if (errno == ENOENT)
				strcpy(resultBuffer, tempBuffer);
		}
		else {
		}
	}


out:

	if (tempBuffer != NULL)
		lwip_bm_free(tempBuffer);


//	LWIP_INFO("TEMP REDIRECT out");
	return result;


}




/* Given a path, will create a redirected copy if the real user 
   has access to it.
*/
int lwip_redirect_createRedirectedCopy(char *path) {

	if (path == NULL)
		return -1;

	LWIP_ASSERT(path[0] == '/', "Only accept absolute path");
	LWIP_ASSERT((strncmp(path, LWIP_REDIRECTION_PATH, strlen(LWIP_REDIRECTION_PATH)) != 0), "Redirected path should not be redirected again");

	int rv = -1;
	char *redirectedPath = lwip_bm_malloc(PATH_MAX);
	sprintf(redirectedPath, LWIP_REDIRECTION_PATH "%s", path);

	if (lwip_util_fileExist(redirectedPath)) {
		rv = 0;
		return 0;
	}

	if (lwip_util_faccessat(AT_FDCWD, path, R_OK, 0)) {
		if (errno == EACCES) {
			LWIP_UNEXPECTED("See if this works fine");
			//Ask delegator to open file in read mode so that we can copy ourselves.

			int originalFD;
			del_pkt_prepare_packets(open, pkt, response);
			strncpy(pkt.pathname, path, PATH_MAX);
			pkt.flags = O_RDONLY;

			if (LWIP_likely(sh_SEND2DELEGATOR(&pkt) == 0) && LWIP_likely(sh_RECVFDFROMDELEGATOR(&response, &originalFD) != -1)) {
				if (response.l_isError) {
					LWIP_INFO("Delegator has no read access to the file %s", path);
					goto out;
				} else {
					LWIP_INFO("Delegator returned %d on open, new fd is %d", response.l_rv, originalFD);

					lwip_createDirsIgnLast_with_permissions(redirectedPath, -1, S_IRWXU|S_IRWXG|S_IROTH|S_IWOTH);
					int redirectedFD = open(redirectedPath, O_WRONLY|O_CREAT|O_EXCL);
					if (redirectedFD < 0) {
						LWIP_UNEXPECTED("Failed to create file in redirected directory %s", redirectedPath);
						close(originalFD);
						goto out;
					}

					if (lwip_copyFileFD(originalFD, redirectedFD)) {
						LWIP_UNEXPECTED("Failed to copy from fd to fd");
					} else
						rv = 0;

					close(originalFD);
					close(redirectedFD);
					goto out;			

				} 
			}

		} else if (errno != ENOENT)
			LWIP_UNEXPECTED("faccessat failed on path %s", path);
		goto out;
	}
	//Has read access

	if (lwip_copyFile(path, redirectedPath, -1, S_IRWXU|S_IRWXG)) {
		LWIP_UNEXPECTED("Copy file procedure failed for path %s", path);
		goto out;
	}

	rv = 0;

out:
	lwip_bm_free(redirectedPath);
	return rv;

}



