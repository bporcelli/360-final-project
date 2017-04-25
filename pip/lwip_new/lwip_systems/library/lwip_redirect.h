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

#ifndef __LWIP_REDIRECT_H_
#define __LWIP_REDIRECT_H_


void convert2FullAndRedirectPathat_re_force(unsigned int *dirfd, unsigned int *reg, char *buffer1, char *buffer2, int force);
//void convert2FullAndRedirectPathat_re(unsigned int *dirfd, unsigned int *reg, char *buffer1, char *buffer2);
#define convert2FullAndRedirectPathat_re(dirfd, reg, buf1, buf2) convert2FullAndRedirectPathat_re_force(dirfd, reg, buf1, buf2, 0)
#define convert2FullAndRedirectPathat_re_F(dirfd, reg, buf1, buf2) convert2FullAndRedirectPathat_re_force(dirfd, reg, buf1, buf2, 1)


void convert2FullAndRedirectPath_re(unsigned int *reg, char *buffer);

void convert2FullPath(unsigned int *reg);
char *getFullandRedirectedPath(int dirfd, char *path, char *resultBuffer);

int lwip_redirect_createRedirectedCopy(char *path);

#endif /* __LWIP_REDIRECT_H_ */

