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

#include "lwip_syscall_handler.h"
#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_common.h"
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include "lwip_ipc.h"
#include "lwip_notifier.h"

#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP       4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24

lwip_callback(deny_shm_ipc_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	LWIP_INFO("IPC is denied");
}


inline lwip_syscall(ipc_h, pre)
{
  prepare_variables1(unsigned int, call);
  switch (call) {
  
  case MSGCTL: {
    prepare_variables4(unsigned int VARIABLE_IS_NOT_USED, call, int VARIABLE_IS_NOT_USED, msqid, int, cmd, struct msqid_ds * VARIABLE_IS_NOT_USED, buf);
    if (cmd == IPC_SET) {
      LWIP_CRITICAL("MSGCTL/IPC_SET is called, should be intercepted to check level");
    }
    break;
  }
  
  case SHMGET: {
    break;
  }
  case SHMAT: {
    int shmid = *p2_ptr;
    if (LWIP_PROCESS_LV_HIGH) {
        struct shmid_ds buf;
        if (shmctl(shmid, IPC_STAT, &buf) != 0) {
          LWIP_CRITICAL("IPC_STAT failed to get shm stat");
          goto out;
        }
        if (lwip_level_isLow(lwip_ipc2Lv(buf.shm_perm))) {
          sh_showUserMsgN("IPC is denied");
          lwip_cancelSyscall(&deny_shm_ipc_post);
          LWIP_VIOLATION("IPC level is untrusted");
        }
    }    
out:
    break;
  }
  case SHMCTL: {
    prepare_variables4(unsigned int VARIABLE_IS_NOT_USED, call, int VARIABLE_IS_NOT_USED, shmid, int, cmd, struct shmid_ds * VARIABLE_IS_NOT_USED, buf);
    if (cmd == IPC_SET) {
      LWIP_CRITICAL("SHMCTL/IPC_SET is called, should be intercepted to check level");
    }
    break;
  }
//  default:
//    LWIP_CRITICAL("IPC is other: %d", call);
  }

}


inline lwip_syscall(ipc_h, post)
{
  prepare_variables1(unsigned int, call);
  switch (call) {
  
 // case MSGCTL:
  case MSGGET: {
    if (LWIP_PROCESS_LV_HIGH) {
      int msqid = (int) *return_value_ptr;
      if (msqid >= 0) {
        struct msqid_ds buf;
        if (msgctl(msqid, IPC_STAT, &buf) != 0) {
          LWIP_CRITICAL("IPC_STAT failed to get msq stat");
          goto out;
        }
        if (lwip_level_isLow(lwip_ipc2Lv(buf.msg_perm)))
          LWIP_VIOLATION("IPC level is untrusted, currently doing nothing to prevent");
      }
    }
out:    
    break;
  }

  case SHMGET: {
    if (LWIP_PROCESS_LV_HIGH) {
      int shmid = (int) *return_value_ptr;
      if (shmid >= 0) {
        struct shmid_ds buf;
        if (shmctl(shmid, IPC_STAT, &buf) != 0) {
          LWIP_CRITICAL("IPC_STAT failed to get msq stat");
          goto out2;
        }
        if (lwip_level_isLow(lwip_ipc2Lv(buf.shm_perm))) {
	  LWIP_INFO("IPC is of low integrity: uid: %d, gid: %d", buf.shm_perm.uid, buf.shm_perm.gid);
	  if (buf.shm_perm.mode & S_IWOTH)
		LWIP_INFO("IPC is world writable");
	  if (buf.shm_perm.mode & S_IWGRP)
		LWIP_INFO("IPC is group writable");
	  if ((buf.shm_perm.mode & S_IWOTH) && (buf.shm_perm.mode & S_IWGRP) && buf.shm_perm.uid == LWIP_CF_REAL_USERID && buf.shm_perm.gid == LWIP_CF_REAL_USERID) {
		LWIP_INFO("Group info of IPC is not used, will use it for trustedgroup");
		buf.shm_perm.gid = LWIP_CF_TRUSTED_GROUP_GID;
		buf.shm_perm.mode &= ~(S_IWOTH);
		if (lwip_level_isLow(lwip_ipc2Lv(buf.shm_perm)))
		  LWIP_INFO("modified IPC is still of low integrity???");

		if (shmctl(shmid, IPC_SET, &buf) != 0) {
			LWIP_INFO("Failed to set the IPC permission");
		}
		goto out2;
	}
          LWIP_VIOLATION("IPC level is untrusted, currently doing nothing to prevent");
	}
      }
    }
    
out2:    
    break;
  }
/*  case SEMCTL: */
  }

}

