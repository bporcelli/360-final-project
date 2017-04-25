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

#ifndef __LWIP_RD_CONF_H__
#define __LWIP_RD_CONF_H__

#include "lwip_level.h"
#include "pthread.h"
#include <unistd.h>
#include <semaphore.h>

#define lm_processInfo_count 5
#define lm_bucketSize 16 


//#define lm_vercount lm_pgrpData_body.ver_count
#define lm_curLevel lm_pgrpData_body.cur_level
#define lm_minLevel lm_pgrpData_body.min_level
#define lm_count lm_pgrpData_body.count
#define lm_verCount lm_pgrpData_body.ver_count
#define lm_violationFlag lm_pgrpData_body.violation_happened

#define lm_per_processInfo lm_pgrpData_body.per_processInfo


struct lwip_rd_lm_processInfo {
	pid_t pid;
	Level cur_level;
	Level min_level;
};



struct lwip_rd_lm_pgrpData_body {
	int ver_count;
	Level cur_level;
	Level min_level;
	int count;
	int violation_happened;
	struct lwip_rd_lm_processInfo per_processInfo[lm_bucketSize][lm_processInfo_count];
};


struct lwip_rd_lm_pgrpData {
	pid_t pgid;
//	pthread_mutex_t write_lock;
	sem_t write_lock;
	struct lwip_rd_lm_pgrpData_body lm_pgrpData_body;
};


#endif /* __LWIP_RD_CONF_H__ */

