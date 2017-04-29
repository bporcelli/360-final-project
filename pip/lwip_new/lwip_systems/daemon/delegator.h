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

#ifndef __LWIP_DELEGATOR_H__
#define __LWIP_DELEGATOR_H__

#include "lwip_del_conf.h"
#include "lwip_debug.h"

/* Macros used to set up delegated system calls. The daemon will call
 * the method process_SYSCALLNAME by default to handle a delegated 
 * syscall. */
#define lwip_del_call(call) int process_ ##call(struct del_pkt_ ##call *req, struct del_pkt_ ##call ##_response *response)
#define lwip_del_iso_call(call) int process_iso_ ##call(struct del_pkt_ ##call *req, struct del_pkt_ ##call ##_response *response)


#define invoke_helperFunction(function, args...) function((struct del_pkt_generic_response *)response, ##args)
#define define_helperFunction(function, args...) void function(struct del_pkt_generic_response *response, ##args)


#define getVariables1(t1, a1) t1 a1 = req->a1;

#define getVariables2(t1, a1, ...) \
	getVariables1(t1, a1) \
	getVariables1(__VA_ARGS__)

#define getVariables3(t1, a1, ...) \
	getVariables1(t1, a1) \
	getVariables2(__VA_ARGS__)

#define getVariables4(t1, a1, ...) \
	getVariables1(t1, a1) \
	getVariables3(__VA_ARGS__)

#define LWIP_SET_RESPONSE_ERROR(err_no) do { \
	response->l_isError = 1; \
	response->l_rv = err_no; \
	if (err_no != ENOENT) \
		LWIP_INFO("Delegator returns error -%d", err_no); \
	} while (0)

#define LWIP_UNSET_RESPONSE_ERROR(rv) do { \
	response->l_isError = 0; \
	response->l_rv = rv; \
	} while (0)

#define WARN_IF_NOT_ABS(path) do { \
	if (path[0] != '/') \
		LWIP_CRITICAL("Path is not absolute: %s", path); \
	} while (0)





#define lwip_del_performOperationAndSetResponse(operation) \
	do { \
		int rv; \
		if ((rv = (operation)) < 0) \
			LWIP_SET_RESPONSE_ERROR(errno); \
		else \
			LWIP_UNSET_RESPONSE_ERROR(rv); \
	} while (0)


	
#endif /* __LWIP_DELEGATOR_H__ */

