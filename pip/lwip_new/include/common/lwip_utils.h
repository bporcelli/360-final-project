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

#ifndef __LWIP_UTILS_H__
#define __LWIP_UTILS_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>


#define lwip_util_getpid() ((pid_t)syscall(SYS_getpid))

int lwip_util_strcmp(const char *s1, const char *s2);
//pid_t lwip_util_gettid();

char *lwip_util_getProcessImagePath();

char *lwip_util_nonSafefd2FullPath(int fd);

int lwip_util_fd2fullPath(int fd, char *path);

int lwip_util_cleanUpPath(char *inputStr, char *outputStr);

int lwip_util_stringInArray(const char *path, const char * const array[]);
int lwip_util_stringInPrefixArray(const char *path, const char * const prefixArray[]);
int lwip_util_intInArray(int num, int array[]);
#define lwip_util_uidInArray(uid, uid_list) lwip_util_intInArray((int)uid, (int *)uid_list)

#define lwip_util_stat(path, buf) stat(path, buf)
#define lwip_util_lstat(path, buf) lstat(path, buf)
#define lwip_util_fstatat(dirfd, path, buf, flag) fstatat(dirfd, path, buf, flag)
#define lwip_util_fstat(fd, buf) fstat(fd, buf)
#define lwip_util_faccessat(dirfd, path, mode, flags) faccessat(dirfd, path, mode, flags)


#define lwip_util_fileExistAt(dirfd, path) \
	((lwip_util_faccessat(dirfd, path, F_OK, 0) == 0) ? 1 : \
	(lwip_util_faccessat(dirfd, path, F_OK, AT_SYMLINK_NOFOLLOW) == 0 ? 1: 0))

#define lwip_util_fileExist(path) lwip_util_fileExistAt(AT_FDCWD, path)



ssize_t lwip_util_send_fd(int fd, void *ptr, size_t nbytes, int sendfd);
ssize_t lwip_util_recv_fd(int fd, void *ptr, size_t nbytes, int *recvfd);

const char *lwip_util_mode2perms(mode_t mode);


int lwip_util_getFullPath(const char *fileName, char *dest);

int lwip_util_closeAllLowIntegrityFile_read();  

int lwip_util_isLastThread();


int lwip_util_downgrade_downgradableFiles();


int lwip_util_isInsideContainer();

int lwip_util_isUserFileBuf(struct stat buf);
int lwip_util_isUserFile(char *filePath);
int lwip_util_isUserFile_fd(int fd);

int lwip_util_downgradeFileAt(int dirfd, const char *filePath, int flag);
#define lwip_util_downgradeFile(file) lwip_util_downgradeFileAt(AT_FDCWD, file, 0)

int lwip_util_downgradeFile_fd(int fd);


int lwip_util_getFullPathAt(int dirfd, const char *path, char *dest);

char *lwip_itoa(int i);


#define LWIP_FLAGISSET(var, flag) (((var) & (flag)) == (flag))

#define LWIP_ISREDIRECTEDPATH(path) (strncmp(path, LWIP_REDIRECTION_PATH, strlen(LWIP_REDIRECTION_PATH)) == 0)


#define lwip_snprintf5(dst, len, count_ptr, type1, value1) lwip_snprintf_ ##type1(dst, len, count_ptr, value1)

#define lwip_snprintf_str(dst, len, count_ptr, value) \
	do { \
		int toprint = strlen(value); \
		if (toprint + *count_ptr > len) \
			toprint = len - *count_ptr; \
		memcpy(dst + *count_ptr, value, toprint); \
		*count_ptr += toprint; \
	} while (0)

#define lwip_snprintf_int(dst, len, count_ptr, value) \
	do { \
		char *str = lwip_itoa(value); \
		int toprint = strlen(str); \
		if (toprint + *count_ptr > len) \
			toprint = len - *count_ptr; \
		memcpy(dst + *count_ptr, str, toprint); \
		*count_ptr += toprint; \
	} while (0)

	
#define lwip_snprintf_template(next, dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		next(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


#define lwip_snprintf7(dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		lwip_snprintf5(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


//	lwip_snprintf_template(lwip_snprintf1, dst, len, count_ptr, type1, value1, __VA_ARGS__);
	

#define lwip_snprintf9(dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		lwip_snprintf7(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


//	lwip_snprintf_template(lwip_snprintf2, dst, len, count_ptr, type1, value1, __VA_ARGS__);
	

#define lwip_snprintf11(dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		lwip_snprintf9(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


//	lwip_snprintf_template(lwip_snprintf3, dst, len, count_ptr, type1, value1, __VA_ARGS__);
	

#define lwip_snprintf13(dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		lwip_snprintf11(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


//	lwip_snprintf_template(lwip_snprintf4, dst, len, count_ptr, type1, value1, __VA_ARGS__);
	

#define lwip_snprintf15(dst, len, count_ptr, type1, value1, ...) \
	do { \
		lwip_snprintf5(dst, len, count_ptr, type1, value1); \
		if (*count_ptr >= len) \
			break; \
		lwip_snprintf13(dst, len, count_ptr, __VA_ARGS__); \
        } while (0)


//	lwip_snprintf_template(lwip_snprintf5, dst, len, count_ptr, type1, value1, __VA_ARGS__);


#define PP_NARG(...) \
    PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
    PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
     _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
    _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
    _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
    _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
    _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
    _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
    _61,_62,_63,  N, ...) N
#define PP_RSEQ_N() \
    63,62,61,60,                   \
    59,58,57,56,55,54,53,52,51,50, \
    49,48,47,46,45,44,43,42,41,40, \
    39,38,37,36,35,34,33,32,31,30, \
    29,28,27,26,25,24,23,22,21,20, \
    19,18,17,16,15,14,13,12,11,10, \
     9, 8, 7, 6, 5, 4, 3, 2, 1, 0


#define glue(a, b) a ## b
#define xglue(a, b) glue(a, b)

	
#define lwip_snprintf(...) xglue(lwip_snprintf, PP_NARG(__VA_ARGS__))( __VA_ARGS__)




/*int lwip_util_convertAt2FullPath(int dirfd, char *pathname, char *buf);



  

*/

#endif /* __LWIP_UTILS_H__ */


