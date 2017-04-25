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

#ifndef __LWIP_TRACKOPEN_H__
#define __LWIP_TRACKOPEN_H__

#include "lwip_common.h"

void lwip_trackOpen_addExplict(char *);
void lwip_trackOpen_addImplict(char *);
int lwip_trackOpen_testIsExplict(char *, int open_flags);

#ifdef LWIP_OS_LINUX

#define LWIP_TRACK_IMPLICIT_EXPLICIT
#define LWIP_SAVE_IMPLICIT_EXPLICIT_TO_FILE

#endif

void lwip_trackOpen_addUntrusted(char *);
int lwip_trackOpen_isUntrusted(char *);


#endif /* __LWIP_TRACKOPEN_H__ */
