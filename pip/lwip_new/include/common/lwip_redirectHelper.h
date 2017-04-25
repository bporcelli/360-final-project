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

#ifndef __LWIP_REDIRECTHELPER_H__
#define __LWIP_REDIRECTHELPER_H__

#include <sys/types.h>

int lwip_copyFile_preservePermission(char *src, char *dst);
int lwip_copyFile(char *src, char *dest, gid_t gid, mode_t mode);

int lwip_copyFileFD(int src, int dst);

int lwip_moveFile_preservePermission(char *src, char *dst);
int lwip_moveFile(char *src, char *dest, gid_t gid, mode_t mode);

int lwip_createDirs_with_permissions_chmod(char *dir, gid_t gid, mode_t mode, int performChmod);
int lwip_createDirsIgnLast_with_permissions_chmod(char *dir, gid_t gid, mode_t mode, int performChmod);

#define lwip_createDirs_with_permissions(dir, gid, mode) lwip_createDirs_with_permissions_chmod(dir, gid, mode, 1)
#define lwip_createDirsIgnLast_with_permissions(dir, gid, mode) lwip_createDirsIgnLast_with_permissions_chmod(dir, gid, mode, 1)

#define lwip_createDirs_nochown_nochmod(dir, mode) lwip_createDirs_with_permissions_chmod(dir, -1, mode, 0)
#define lwip_createDirsIgnLast_nochown_nochmod(dir, mode) lwip_createDirsIgnLast_with_permissions_chmod(dir, -1, mode, 0)


int lwip_createDirsIgnLast(char *dir, mode_t mode);
int lwip_createDirs(char *dir, mode_t mode);


#endif /* __LWIP_REDIRECTHELPER_H__ */


