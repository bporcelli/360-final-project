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

#include "lwip_socket.h"

#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_del_conf.h"
#include "lwip_delegator_connection.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>

#ifdef LWIP_OS_LINUX
#include <linux/net.h>
#endif


lwip_syscall(getsockopt_h, post) {
#ifdef LWIP_INTERCEPT_DBUS_MESSAGE
	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);

	int optname = args[2];
	void *optval = (void *)args[3];

/* Not SO_PASSCRED!!! */
	if (optname == SO_PEERCRED) {
		struct CREDSTRUCT *ucred = (struct CREDSTRUCT *)optval;
#ifdef LWIP_OS_LINUX
		if (ucred->uid == LWIP_CF_UNTRUSTED_USERID)
			ucred->uid = LWIP_CF_REAL_USERID;
		if (ucred->gid == LWIP_CF_UNTRUSTED_USERID)
			ucred->gid = LWIP_CF_REAL_USERID;
#elif defined LWIP_OS_BSD
		if (ucred->cmcred_uid == LWIP_CF_UNTRUSTED_USERID)
			ucred->cmcred_uid = LWIP_CF_REAL_USERID;
		if (ucred->cmcred_gid == LWIP_CF_UNTRUSTED_USERID)
			ucred->cmcred_gid = LWIP_CF_REAL_USERID;
		if (ucred->cmcred_euid == LWIP_CF_UNTRUSTED_USERID)
			ucred->cmcred_euid = LWIP_CF_REAL_USERID;
#endif
	}

#endif
}


#ifdef LWIP_OS_LINUX

lwip_syscall(socketcall_h, post)
{
	prepare_variables1(int, call);
	switch (call) {
		case SYS_GETSOCKOPT: lwip_call(getsockopt_h, post); break;
	}
}

#endif

