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

#include "lwip_getuid.h"
#include "lwip_syscall_handler.h"

#include "lwip_level.h"
#include "lwip_common.h"
#include "lwip_debug.h"

inline lwip_syscall(getxuid_l, post) {
	if (*return_value_ptr == LWIP_CF_UNTRUSTED_USERID)
		*return_value_ptr = LWIP_CF_REAL_USERID;
}

inline lwip_syscall(getxgid_l, post) {
	if (*return_value_ptr == LWIP_CF_UNTRUSTED_USERID)
		*return_value_ptr = LWIP_CF_REAL_USERID;
}

inline lwip_syscall(getresuid_l, post) {
	uid_t *ruid = (uid_t*)*p1_ptr;
	uid_t *euid = (uid_t*)*p2_ptr;
	uid_t *suid = (uid_t*)*p3_ptr;

	if (*ruid == LWIP_CF_UNTRUSTED_USERID)
		*(uid_t*)*p1_ptr = LWIP_CF_REAL_USERID;

	if (*euid == LWIP_CF_UNTRUSTED_USERID)
		*(uid_t*)*p2_ptr = LWIP_CF_REAL_USERID;

	if (*suid == LWIP_CF_UNTRUSTED_USERID)
		*(uid_t*)*p3_ptr = LWIP_CF_REAL_USERID;
}

inline lwip_syscall(getresgid_l, post) {
	gid_t *rgid = (gid_t*)*p1_ptr;
	gid_t *egid = (gid_t*)*p2_ptr;
	gid_t *sgid = (gid_t*)*p3_ptr;

	if (*rgid == LWIP_CF_UNTRUSTED_USERID)
		*(gid_t*)*p1_ptr = LWIP_CF_REAL_USERID;

	if (*egid == LWIP_CF_UNTRUSTED_USERID)
		*(gid_t*)*p2_ptr = LWIP_CF_REAL_USERID;

	if (*sgid == LWIP_CF_UNTRUSTED_USERID)
		*(gid_t*)*p3_ptr = LWIP_CF_REAL_USERID;
}

lwip_syscall(setxuid_l, pre) {
	prepare_variables1(uid_t, uid);
	if (uid == LWIP_CF_REAL_USERID)
		*p1_ptr = LWIP_CF_UNTRUSTED_USERID;

}


inline lwip_syscall(setresuid_l, pre)
{
	prepare_variables3(uid_t, ruid, uid_t, euid, uid_t, suid);

	if (LWIP_PROCESS_LV_LOW) {
		LWIP_INFO("Want to convert resuid to %d, %d, %d", ruid, euid, suid);
		if (ruid == LWIP_CF_REAL_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (ruid == LWIP_CF_ROOT_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (euid == LWIP_CF_REAL_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (euid == LWIP_CF_ROOT_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (suid == LWIP_CF_REAL_USERID)
			*p3_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (suid == LWIP_CF_ROOT_USERID)
			*p3_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;
	}

}

inline lwip_syscall(setresgid_l, pre)
{
	prepare_variables3(uid_t, ruid, uid_t, euid, uid_t, suid);

	if (LWIP_PROCESS_LV_LOW) {
		LWIP_INFO("Want to convert resgid to %d, %d, %d", ruid, euid, suid);
		if (ruid == LWIP_CF_REAL_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (ruid == LWIP_CF_ROOT_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (euid == LWIP_CF_REAL_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (euid == LWIP_CF_ROOT_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (suid == LWIP_CF_REAL_USERID)
			*p3_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (suid == LWIP_CF_ROOT_USERID)
			*p3_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;
	}
}

lwip_syscall(setregid_l, pre)
{
	prepare_variables2(uid_t, ruid, uid_t, euid);

	if (LWIP_PROCESS_LV_LOW) {
		LWIP_INFO("Want to convert regid to %d, %d", ruid, euid);
		if (ruid == LWIP_CF_REAL_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (ruid == LWIP_CF_ROOT_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (euid == LWIP_CF_REAL_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (euid == LWIP_CF_ROOT_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;
	}
}

inline lwip_syscall(setreuid_l, pre)
{
	prepare_variables2(uid_t, ruid, uid_t, euid);

	if (LWIP_PROCESS_LV_LOW) {
		LWIP_INFO("Want to convert reuid to %d, %d", ruid, euid);
		if (ruid == LWIP_CF_REAL_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (ruid == LWIP_CF_ROOT_USERID)
			*p1_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

		if (euid == LWIP_CF_REAL_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTED_USERID;
		if (euid == LWIP_CF_ROOT_USERID)
			*p2_ptr = LWIP_CF_UNTRUSTEDROOT_USERID;

	}

}

lwip_syscall(setgroups_l, pre) {
#ifdef LWIP_DEBUG_ON
	prepare_variables2(size_t, size, gid_t *, list);
	if (LWIP_PROCESS_LV_LOW) {
		LWIP_INFO("setgroups is called with size %d", size);
		int i;
		for (i=0; i<size; i++)
			LWIP_INFO("group %d is %d", i, list[i]);
	}
#endif
}


lwip_syscall(setgroups_l, post) {
	prepare_variables2(size_t, size, gid_t *, list);
	if (LWIP_PROCESS_LV_LOW && LWIP_ISERROR && lwip_syscall_errno == EPERM) {

		int existingGroupCount = getgroups(0, NULL);
		gid_t *existingList = malloc(sizeof(gid_t)*existingGroupCount);
		if (getgroups(existingGroupCount, existingList) == -1) {
			LWIP_INFO("Failed to do getgroups %d", errno);
			goto out;
		}

		int temp, temp2;
		int *existingListShouldHaveRemoved = calloc(existingGroupCount, sizeof(int));
		
		for (temp=0; temp<size; temp++) {
			for (temp2=0; temp2<existingGroupCount; temp2++) {
				if (existingList[temp2] == list[temp]) {
					existingListShouldHaveRemoved[temp2] = 1;
					goto searchNext;
				}
			}
			LWIP_CRITICAL("setgroups is called to have a group existing process does not satisfy: %d", list[temp]);
searchNext:
			continue;
		}

		for (temp2=0; temp2<existingGroupCount; temp2++)
			if (existingListShouldHaveRemoved[temp2] == 0)
				LWIP_CRITICAL("setgroups should not have gid %d, but is not removed right now.", existingList[temp2]);

		//TODO:
		LWIP_UNSET_SYSCALL_ERROR(0);

		free(existingListShouldHaveRemoved);
out:
		free(existingList);

	}


	return;

}


