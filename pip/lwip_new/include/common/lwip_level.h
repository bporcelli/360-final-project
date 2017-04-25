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

#ifndef __LWIP_LEVEL_H__
#define __LWIP_LEVEL_H__


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ipc.h>
#include "lwip_common.h"
#include "lwip_debug.h"

/**
 * LV_* define quantitatively the integrity level
 */
#define LV_HIGH 2
#define LV_LOW 1
#define LV_UNKNOWN -1
#define LV_ERROR -1

typedef int Level;

//Files can be safely downgraded via chmod, or files that can be downgraded automatically
extern const char * const lwip_trusted2DowngradeFiles[];
extern const char * const lwip_trusted2DowngradeDirs[];

extern const char * const lwip_trusted2OpenReadingFiles[];
extern const char * const lwip_trusted2OpenReadingDirs[];

extern const char * const lwip_redirectableFiles[];
extern const char * const lwip_redirectableDirs[];

extern const char * const lwip_lowICanWriteFiles[];
extern const char * const lwip_lowICanWriteDirs[];




#define level_isGt(l1, l2) (l1 > l2)
#define level_isGe(l1, l2) (l1 >= l2)
#define level_isEq(l1, l2) (l1 == l2)

#define lwip_level_isGt(l1, l2) (l1 > l2)
#define lwip_level_isGe(l1, l2) (l1 >= l2)
#define lwip_level_isEq(l1, l2) (l1 == l2)

#define lwip_level_min(l1, l2) (l1 < l2 ? l1 : l2)
#define lwip_level_max(l1, l2) (l1 > l2 ? l1 : l2)

#define lwip_uid2Lv(uid) ((uid == LWIP_CF_UNTRUSTED_USERID || uid == LWIP_CF_UNTRUSTEDROOT_USERID) ? LV_LOW : LV_HIGH)
#define lwip_gid2Lv(gid) ((gid == LWIP_CF_UNTRUSTED_USERID || gid == LWIP_CF_UNTRUSTEDROOT_USERID) ? LV_LOW : LV_HIGH)

#define level_min(l1, l2) (l1 < l2 ? l1 : l2)
#define level_max(l1, l2) (l1 > l2 ? l1 : l2)

#define level_isUntrustedUid(uid) (lwip_uid2Lv(uid) == LV_LOW ? 1 : 0)
#define level_isTrustedUid(uid) (lwip_uid2Lv(uid) == LV_HIGH ? 1 : 0)

#define lwip_level_isLow(level) ( level == LV_LOW ? 1 : 0)
#define lwip_level_isHigh(level) ( level == LV_HIGH ? 1 : 0)

int lwip_isUntrustedBuf(struct stat buf);

Level lwip_file2Lv_read(char *file_path);
Level lwip_file2Lv_write(char *file_path);
Level lwip_file2Lv_write2(char *file_path, struct stat buf);

Level lwip_fd2Lv_read(int fd);
Level lwip_fd2Lv_read_wh(int fd, char *hint);
Level lwip_fd2Lv_write(int fd);
Level lwip_fd2Lv_exec(int fd);
Level lwip_fd2Lv_exec_wh(int fd, char *hint);
Level lwip_fd2Lv_read_newMode2(int fd, mode_t mode);
Level lwip_fd2Lv_read_newOwner3(int fd, uid_t uid, gid_t gid);
Level lwip_fd2Lv_read_newOwner4(int fd, uid_t uid, gid_t gid, struct stat buf);

Level lwip_file2Lv_read_newOwner3(char *path, uid_t owner, gid_t group);
Level lwip_file2Lv_read_newOwner4(char *path, uid_t owner, gid_t group, struct stat buf);
Level lwip_file2Lv_read_newMode(char *path, mode_t mode);
Level lwip_file2Lv_read_newMode3(char *path, mode_t mode, struct stat buf);

Level lwip_ipc2Lv(struct ipc_perm);




uid_t level_utUid2realUid(uid_t untrustedUid);
uid_t level_realUid2utUid(uid_t untrustedUid);

int lwip_isDowngradableFile(const char *path);

int lwip_genericAtChecking(int dirfd, const char *pathname, const char * const *prefixArray, const char * const *stringArray);

#define lwip_isTrusted2DowngradeFileAt(dirfd, pathname) lwip_genericAtChecking(dirfd, pathname, lwip_trusted2DowngradeDirs, lwip_trusted2DowngradeFiles)
#define lwip_isTrusted2DowngradeFile(path) lwip_isTrusted2DowngradeFileAt(AT_FDCWD, path)

#define lwip_isTrusted2OpenAt(dirfd, pathname) lwip_genericAtChecking(dirfd, pathname, lwip_trusted2OpenReadingDirs, lwip_trusted2OpenReadingFiles)
#define lwip_isTrusted2Open(path) lwip_isTrusted2OpenAt(AT_FDCWD, path)


#define lwip_isRedirectableFileAt(dirfd, pathname) lwip_genericAtChecking(dirfd, pathname, lwip_redirectableDirs, lwip_redirectableFiles)
//#define lwip_isRedirectableFile(path) lwip_isRedirectableFileAt(AT_FDCWD, path)

int lwip_isRedirectableSM(const char *path);

#define lwip_isRedirectableFile(path) lwip_isRedirectableSM(path)


#define lwip_isLowICanWriteAt(dirfd, pathname) lwip_genericAtChecking(dirfd, pathname, lwip_lowICanWriteDirs, lwip_lowICanWriteFiles)
#define lwip_isLowICanWrite(path) lwip_isLowICanWriteAt(AT_FDCWD, path)

#define lwip_isDowngradableFile(path) lwip_isTrusted2DowngradeFile(path)
#define lwip_isDowngradableFileAt(dirfd, pathname) lwip_isTrusted2DowngradeFileAt(dirfd, pathname)



int lwip_file2readLvIsHighat3(int dirfd, const char *path, int flag);
int lwip_file2readLvIsHighat3b(int dirfd, const char *path, struct stat buf);

#define lwip_file2readLvIsLow3b(dirfd, path, buf) (!lwip_file2readLvIsHighat3b(dirfd, path, buf))


//int lwip_file2readLvIsLowat3b(int dirfd, const char *path, struct stat buf);
//int lwip_file2readLvIsLowat3(int dirfd, const char *path, int flag);

Level lwip_level_statLv(struct stat buf);
Level lwip_level_statNewOwnerLv(struct stat buf, uid_t owner, gid_t group);
Level lwip_level_statNewModeLv(struct stat buf, mode_t mode);



#endif /* __LWIP_LEVEL_H__ */

