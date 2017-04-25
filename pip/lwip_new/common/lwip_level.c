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

/*******************************************************
 * level.c:
 * Level specific functions and implementation
 *******************************************************/

#include "lwip_utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "lwip_debug.h"
#include "lwip_common.h"
#include "lwip_level.h"
#include <limits.h>
#include "lwip_bufferManager.h"
#include "strmap.h"

/* Files that are world writable, but is considered to be of highI for reading */

#ifdef LWIP_OS_BSD
const char * const lwip_trusted2OpenReadingFiles[] = {
  "/tmp/.X11-unix",
  "/tmp/.XIM-unix",
  "/tmp/.ICE-unix",
  "/tmp/.font-unix",
  "/var/tmp/vi.recover",
  LWIP_LOG_FILES,
  NULL
};

const char * const lwip_trusted2OpenReadingDirs[] = {
        "/dev",
        "/proc",
        NULL
};

const char * const lwip_lowICanWriteFiles[] = {
        "/home/bsd/.qt/.qt_plugins_3.3rc.lock",
        NULL
};

const char * const lwip_lowICanWriteDirs[] = {
        "/dev/pts",
        NULL
};

const char * const lwip_redirectableFiles[] = {
        NULL
};

const char * const lwip_redirectableDirs[] = {
	"/home/bsd/.",
	"/usr/home/bsd/.",
	NULL
};

const char * const lwip_trusted2DowngradeFiles[] = {
  "/home/" LWIP_CF_REAL_USERNAME "/Documents/output.txt",
  NULL
};


const char * const lwip_trusted2DowngradeDirs[] = {
        "/home/" LWIP_CF_REAL_USERNAME "/.pulse/",
        NULL
};

#elif defined LWIP_OS_LINUX

//////////////////////////////////////////////////////////

const char * const lwip_trusted2DowngradeFiles[] = {
        "/dev/vboxuser",
        "/var/run/dbus/system_bus_socket",
        "/dev/log",
        "/tmp/.X11-unix",
        "/tmp/.ICE-unix",
        "/var/run/acpid.socket",
        "/tmp/.esd-1000/socket",
        NULL
};

const char * const lwip_trusted2DowngradeDirs[] = {

        "/home/" LWIP_CF_REAL_USERNAME "/.pulse/",
        NULL
};

const char * const lwip_trusted2OpenReadingFiles[] = {
        "/tmp/.X11-unix",
        "/etc/mtab.tmp",
        "/home/" LWIP_CF_REAL_USERNAME "/.xsession-errors",
        "/home/" LWIP_CF_REAL_USERNAME "/.dmrc",
        LWIP_LOG_FILES,
        LWIP_SI_PRIVATE_COPY_ROOT "/home/" LWIP_CF_REAL_USERNAME "/Desktop/info2",
        LWIP_SI_PRIVATE_COPY_ROOT "/home/" LWIP_CF_REAL_USERNAME "/Desktop/all2",
        LWIP_SI_PRIVATE_COPY_ROOT "/home/" LWIP_CF_REAL_USERNAME "/Desktop/critical2",
        //  LWIP_SI_PRIVATE_COPY_ROOT "/var/lib/dpkg/status",
        "/var/run/dbus/system_bus_socket",
        "/var/lib/dpkg/triggers/Lock",
        NULL
};


const char * const lwip_trusted2OpenReadingDirs[] = {
  	"/home/" LWIP_CF_REAL_USERNAME "/benchmark/cpu2006/",
        "/dev/",
//	"socket:[", //Chromium will start with this opened
        LWIP_REDIRECTION_PATH, /* /tmp/redirection ???*/
        "/var/run/gdm/auth-for",
        "/var/cache/gdm/" LWIP_CF_REAL_USERNAME "/dmrc",
        "/proc", //sound will fail as it will do a stat
	"/lwip/extendedLogging/",
        NULL
};





/* removeOnDowngrade are files that should be removed when the process
   is downgraded. It is intended for use with socket. The rationale behind
   is, unlike file, socket cannot be closed, or it may have side effect.
   But highI processes connected will still be affected!!!.
   By removing it, we prevent 

Downgrade socket??? and needs to intercept on reads on socket to check
level???*/


const char * const lwip_redirectableFiles[] = {
  NULL
};


const char * const lwip_redirectableDirs[] = {
/*  "/home/" LWIP_CF_REAL_USERNAME "/.mozilla", //firefox
  "/home/" LWIP_CF_REAL_USERNAME "/.openoffice.org",*/
  "/home/" LWIP_CF_REAL_USERNAME "/.",
  NULL
};


//XXX: Double check if these are necessary
const char * const lwip_lowICanWriteFiles[] = {
  "/home/" LWIP_CF_REAL_USERNAME "/.openoffice.org/3/.lock",
  "/home/" LWIP_CF_REAL_USERNAME "/.xsession-errors",
  "/dev/pts/1", 
  "/dev/pts/0", 
  NULL
};

const char * const lwip_lowICanWriteDirs[] = {
  "/home/" LWIP_CF_REAL_USERNAME "/.execooo",
  "/dev/",
  "pipe",
  "socket",
  "anon_inode",
  "/tmp/",
  NULL
};




#endif


//realUserList stores a list of real uid of the system
static uid_t realUserList[] = { LWIP_CF_REAL_USERID, -1 };

//ut_uid stores a list of ut uid of the system, corresponding to the realUserList
static uid_t ut_uid[] = { LWIP_CF_UNTRUSTED_USERID, -1 };


Level _stat2Lv(struct stat buf);

uid_t level_utUid2realUid(uid_t untrustedUid)
{
  int count = 0;
  while (ut_uid[count] != -1) {
    if (ut_uid[count] == untrustedUid)
      return realUserList[count];
    count++;
  }
  LWIP_CRITICAL("Trying to convert untrusted uid %d which is not untrusted.", untrustedUid);
  return -1;
}


uid_t level_realUid2utUid(uid_t realUid)
{
  int count = 0;
  
  if (realUid == -1)
    realUid = getuid();
    
  while (realUserList[count] != -1) {
    if (realUserList[count] == realUid)
      return ut_uid[count];
    count++;
  }
  
  LWIP_CRITICAL("Trying to convert real uid %d which is not real.", realUid);
  return -1;
}


Level lwip_file2Lv_exec(char *path){
  struct stat buf;
  lwip_util_stat(path, &buf);

  //If the file is installed from untrusted package
  if (lwip_level_isLow(lwip_gid2Lv(buf.st_gid)))
    return LV_LOW;
  return lwip_file2Lv_read(path);
}


/***************************************************
 * Return the level of the file based on
 * 1. file name (if specially specified)
 * 2. if file name doesn't match, based on stat info given
 * 3. if it is a directory, return LV_ROOT
 ***************************************************/
Level lwip_file2Lv_read(char *filePath) {
	if (lwip_util_stringInArray(filePath, lwip_trusted2OpenReadingFiles)
		|| lwip_util_stringInPrefixArray(filePath, lwip_trusted2OpenReadingDirs))
		return LV_HIGH;

	struct stat buf;
	if (lwip_util_stat(filePath, &buf) == 0)
		return _stat2Lv(buf);

	LWIP_CRITICAL("Failed to get level of file %s, errno: %d", filePath, errno);
	return LV_LOW;
}


__thread char fd2Lv_path[PATH_MAX];

Level lwip_fd2Lv_read(int fd) {

	//static char fd2Lv_readpath[PATH_MAX];	
	if (lwip_util_fd2fullPath(fd, fd2Lv_path) == -1)
		goto return_error;

//	return LV_HIGH;
	char *filePath = fd2Lv_path;
	struct stat buf;

	if (lwip_util_stringInArray(filePath, lwip_trusted2OpenReadingFiles)
			|| lwip_util_stringInPrefixArray(filePath, lwip_trusted2OpenReadingDirs))
		return LV_HIGH;

	if (lwip_util_fstat(fd, &buf) == 0) {
		if (S_ISDIR(buf.st_mode))
			return LV_HIGH;
		else 
			return _stat2Lv(buf);
	}
return_error:
//	LWIP_CRITICAL("Failed to get level of file %s, errno: %d. Assuming file is LowI for reading", filePath, errno);
	return LV_HIGH;
	return LV_LOW;  
}

Level lwip_fd2Lv_read_wh(int fd, char *hint) {
	struct stat buf;
	lwip_util_fd2fullPath(fd, fd2Lv_path);
	char *filePath = fd2Lv_path;

	if (fd2Lv_path[0] == '-') {
		if (hint != NULL)
			filePath = hint;
		else {
			LWIP_CRITICAL("Failed to convert fd to full path without hint, forcing low integrity");
			return LV_LOW;
		}
	}  
	


	if (lwip_util_stringInArray(filePath, lwip_trusted2OpenReadingFiles)
			|| lwip_util_stringInPrefixArray(filePath, lwip_trusted2OpenReadingDirs))
		return LV_HIGH;

	if (lwip_util_fstat(fd, &buf) == 0) {
		if (S_ISDIR(buf.st_mode))
			return LV_HIGH;
		else 
			return _stat2Lv(buf);
	}

	LWIP_CRITICAL("Failed to get level of file %s, errno: %d. Assuming file is LowI for reading", filePath, errno);
	return LV_LOW;
}

/*
Level lwip_file2Lv_read_newMode(char *path, mode_t mode)
{
  struct stat buf;
  lwip_util_stat(path, &buf);

  if (S_ISDIR(buf.st_mode))
    return LV_HIGH;
  return lwip_file2Lv_read_newMode3(path, mode, buf);
}

Level lwip_file2Lv_read_newMode3(char *path, mode_t mode, struct stat buf)
{
  if (S_ISDIR(buf.st_mode))
    return LV_HIGH;
  if (lwip_util_stringInArray(path, lwip_trusted2OpenReadingFiles)
		  || lwip_util_stringInPrefixArray(path, lwip_trusted2OpenReadingDirs))
	  return LV_HIGH;

  buf.st_mode = mode;
  return _stat2Lv(buf);
}


Level lwip_fd2Lv_read_newMode2(int fd, mode_t mode) {
  lwip_util_fd2fullPath(fd, fd2Lv_path);
  return lwip_file2Lv_read_newMode(fd2Lv_path, mode);
}
*/

Level lwip_fd2Lv_exec(int fd){
  struct stat buf;

  lwip_util_fstat(fd, &buf);
  
  if (lwip_level_isLow(lwip_gid2Lv(buf.st_gid)))
    return LV_LOW;
  //XXX: Incomplete???
  return level_min(lwip_uid2Lv(buf.st_uid), lwip_gid2Lv(buf.st_gid));

}

Level lwip_fd2Lv_exec_wh(int fd, char *hint){
  struct stat buf;

  lwip_util_fstat(fd, &buf);
  
  if (lwip_level_isLow(lwip_gid2Lv(buf.st_gid)))
    return LV_LOW;

  //XXX: Incomplete???
  return lwip_fd2Lv_read_wh(fd, hint);
//level_min(lwip_uid2Lv(buf.st_uid), lwip_gid2Lv(buf.st_gid));
}



/*
Level lwip_fd2Lv_read_newOwner3(int fd, uid_t uid, gid_t gid) {
  lwip_util_fd2fullPath(fd, fd2Lv_path);
  return lwip_file2Lv_read_newOwner3(fd2Lv_path, uid, gid);
}

Level lwip_fd2Lv_read_newOwner4(int fd, uid_t uid, gid_t gid, struct stat buf) {
  lwip_util_fd2fullPath(fd, fd2Lv_path);
  return lwip_file2Lv_read_newOwner4(fd2Lv_path, uid, gid, buf);
}

Level lwip_file2Lv_read_newOwner3(char *path, uid_t owner, gid_t group)
{
  struct stat buf;
  lwip_util_stat(path, &buf);
  return lwip_file2Lv_read_newOwner4(path, owner, group, buf);
}


Level lwip_file2Lv_read_newOwner4(char *path, uid_t owner, gid_t group, struct stat buf)
{
  if (S_ISDIR(buf.st_mode))
    return LV_HIGH;
  if (lwip_util_stringInArray(path, lwip_trusted2OpenReadingFiles)
		  || lwip_util_stringInPrefixArray(path, lwip_trusted2OpenReadingDirs))
	  return LV_HIGH;

  buf.st_uid = owner;
  buf.st_gid = group;

  return _stat2Lv(buf);
}

*/

/****************************************************
 * Return the level of the file for writing
 * ???? Is this function really necessary ????
 ****************************************************/
Level lwip_file2Lv_write(char* path){

  struct stat buf;

  if (LWIP_likely(lwip_util_stat(path, &buf) == 0))
    return lwip_file2Lv_write2(path, buf);

  if (lwip_isLowICanWrite(path))
    return LV_LOW;  

  LWIP_CRITICAL("Failed to get level of (%s), errno: %d. Assuming file is HighI for writing", path, errno);
  return LV_HIGH;
}

__thread char fd2Lv_path[PATH_MAX];
Level lwip_fd2Lv_write(int fd) {
	struct stat buf;
  lwip_util_fd2fullPath(fd, fd2Lv_path);
  lwip_util_fstat(fd, &buf);
  return lwip_file2Lv_write2(fd2Lv_path, buf);
}



Level lwip_file2Lv_write2(char* path, struct stat buf){
    if (lwip_isLowICanWrite(path))
	    return LV_LOW;

  return _stat2Lv(buf);
}



Level lwip_level_statLv(struct stat buf) {
	return _stat2Lv(buf);
}

Level lwip_level_statNewOwnerLv(struct stat buf, uid_t owner, gid_t group) {
	buf.st_uid = owner;
	buf.st_gid = group;
	return _stat2Lv(buf);
}


Level lwip_level_statNewModeLv(struct stat buf, mode_t mode) {
	buf.st_mode = (buf.st_mode & S_IFMT) | mode;
	return _stat2Lv(buf);
}




/****************************************************
 * Return the level according to the stat buf
 ***************************************************/
Level _stat2Lv(struct stat buf)
{
  mode_t mode = buf.st_mode;

  if ((S_ISDIR(mode) && (mode & S_ISVTX))|| S_ISSOCK(mode))
	return LV_HIGH;

  //Check again: dbus may need to connect to /var/run/dbus/system_bus_socket!!
//  if (S_ISSOCK(mode))
//	return LV_HIGH;

  if (mode & S_IWOTH)
    return LV_LOW;

  return level_min(lwip_uid2Lv(buf.st_uid), lwip_gid2Lv(buf.st_gid));


/*  else if ((mode & S_IWGRP)){
    return level_min(lwip_uid2Lv(buf.st_uid), lwip_gid2Lv(buf.st_gid));
  } else
    return lwip_uid2Lv(buf.st_uid);
*/
}


int lwip_genericAtChecking(int dirfd, const char *pathname, const char * const *prefixArray, const char * const *stringArray) {

	char *path = (char *)pathname, *buffer = NULL;
	int rv = 0;

	if (path[0] != '/') {
		buffer = lwip_bm_malloc(PATH_MAX);
		path = buffer;
		if (lwip_util_getFullPathAt(dirfd, pathname, path)) {
			LWIP_UNEXPECTED("Failed to convert at path with dirfd: %d, pathname: %s", dirfd, pathname);
			goto out;
		}
	}
	rv = (lwip_util_stringInPrefixArray(path, prefixArray) || lwip_util_stringInArray(path, stringArray));

out:
	if (buffer != NULL)
		lwip_bm_free(buffer);
	return rv;
}




Level lwip_ipc2Lv(struct ipc_perm perm) {

  mode_t mode = perm.mode;
  Level ownerLv = level_min(lwip_uid2Lv(perm.uid), lwip_uid2Lv(perm.cuid));

  if (mode & S_IWOTH) {
    LWIP_INFO("IPC is world writable");
    return LV_LOW;
  } else if ((mode & S_IWGRP)){
    LWIP_INFO("IPC is not world writable, but group writable");
    return level_min(ownerLv, lwip_gid2Lv(perm.gid));
  } else
    LWIP_INFO("IPC depends on owner level");
  return ownerLv;
}

int lwip_isUntrustedBuf(struct stat buf) {
	if (((buf.st_gid == LWIP_CF_UNTRUSTED_USERID)/* && (buf.st_mode & S_IWGRP)*/) ||
		buf.st_uid == LWIP_CF_UNTRUSTED_USERID)
		return 1;
	return 0;
}


int lwip_file2readLvIsHighat3(int dirfd, const char *path, int flag) {
	struct stat buf;
	if (lwip_util_fstatat(dirfd, path, &buf, flag))
		return 1;
	return lwip_file2readLvIsHighat3b(dirfd, path, buf);
}


int lwip_file2readLvIsHighat3b(int dirfd, const char *path, struct stat buf) {
	if (_stat2Lv(buf) == LV_HIGH)
		return 1;

	if (lwip_isTrusted2OpenAt(dirfd, path))
		return 1;
	return 0;
}


StrMap *lwip_redirectableSM = NULL;

int lwip_isRedirectableSM(const char *path) {
	int rv = 0;
	if (lwip_redirectableSM == NULL) {
		lwip_redirectableSM = sm_new(50);
		if (lwip_redirectableSM == NULL) {
			LWIP_CRITICAL("Failed to create hash table for redirectable files");
			goto out;
		}

		char *redirectableList = lwip_bm_malloc(PATH_MAX);
		sprintf(redirectableList, LWIP_TRACKOPEN_DIR "/%s.openTrace.redirect", lwip_util_getProcessImagePath());
		FILE *logFile = fopen(redirectableList, "r");
		lwip_bm_free(redirectableList);

		if (logFile == NULL)
			goto out;

		char *input = lwip_bm_malloc(PATH_MAX);
		while (fgets(input, PATH_MAX, logFile) != NULL) {
			input[strlen(input)-1] = 0;
			if (!sm_put(lwip_redirectableSM, input, "redirect"))
				LWIP_CRITICAL("Failed to add entry to hash table %s", input);
			else
				LWIP_CRITICAL("Adding %s to table", input);
		}
		lwip_bm_free(input);
		fclose(logFile);
	}

	if (sm_exists(lwip_redirectableSM, path))
		rv = 1;

out:
/*	if (rv != lwip_isRedirectableFileAt(AT_FDCWD, path))
		LWIP_CRITICAL("Redirection different: Old: %d, New: %d, path: %s", lwip_isRedirectableFileAt(AT_FDCWD, path), rv, path);
	else
		LWIP_CRITICAL("Redirection same: Old: %d, New: %d, path: %s", lwip_isRedirectableFileAt(AT_FDCWD, path), rv, path);
*/
	return rv;
}


