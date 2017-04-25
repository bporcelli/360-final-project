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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "lwip_utils.h"
#include "lwip_notifier.h"

#define LWIP_SHOWUSERMSG_MAX_SIZE 200

__thread char notify_send_msg_buf[LWIP_SHOWUSERMSG_MAX_SIZE];
__thread char notify_send_format_buf[LWIP_SHOWUSERMSG_MAX_SIZE];

void sh_showUserMsgN(char *format, ...) {
  va_list args;
  va_start(args, format);
  vsnprintf(notify_send_format_buf, LWIP_SHOWUSERMSG_MAX_SIZE, format, args);
  va_end(args);
  sh_showUserMsg(notify_send_format_buf);
}

void sh_showUserMsg(char *msg) 
{
  snprintf(notify_send_msg_buf, LWIP_SHOWUSERMSG_MAX_SIZE, "notify-send \"LWIP Message from %s\" \"%s\"", lwip_util_getProcessImagePath(), msg);
  system(notify_send_msg_buf);
}

