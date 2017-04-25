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

#ifndef __LWIP_DELEGATOR_CONNECTION_H_
#define __LWIP_DELEGATOR_CONNECTION_H_

#include "lwip_del_conf.h"

#define sh_SEND2DELEGATOR(pkt) sh_sendPkt2delegator((struct del_pkt *)(pkt))
#define sh_RECVFROMDELEGATOR(pkt) sh_recvPktFromDelegator((struct del_pkt *)((char *)pkt))

int sh_sendPkt2delegator(struct del_pkt *pkt);
int sh_recvPktFromDelegator(struct del_pkt *pkt);

extern int sh_delegatorSocket;

#define sh_RECVFDFROMDELEGATOR(response, newfd) (lwip_util_recv_fd(sh_delegatorSocket, (struct del_pkt *)response, ((struct del_pkt *)response)->l_size, newfd))
#define sh_SENDFDTODELEGATOR(pkt, fd) lwip_util_send_fd(sh_delegatorSocket, (struct del_pkt *)pkt, ((struct del_pkt *)pkt)->l_size, fd)


void sh_closeDelegatorSocket();


#define sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response) ((sh_SEND2DELEGATOR(&pkt) == 0 && sh_RECVFROMDELEGATOR(&response) == 0)? 1 : 0 )

#define sh_COPYRESPONSE(response) \
	do { \
		if (response.l_isError) \
			LWIP_SET_SYSCALL_ERROR(response.l_rv); \
		else \
			LWIP_UNSET_SYSCALL_ERROR(response.l_rv); \
	} while (0)

#endif /* __LWIP_DELEGATOR_CONNECTION_H_ */

