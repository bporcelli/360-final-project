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

#ifndef __LWIP_TRUSTED_H__
#define __LWIP_TRUSTED_H__

#define trustedContext_signature (char *imagePath, char **argv, char **envp)

typedef struct trustedExecutableConfinementStructure {
        char imagePath[PATH_MAX];
        /* To check the parameters */
	const char * const *openWithoutDowngradingDir;
	int inheritable_trust;	/* Whether the trust can be inherited by the child processes */
	int (*trustedContextFn) trustedContext_signature;
} TrustedExe_CS;


int lwip_trusted_isTrustedExectuable();
int lwip_trusted_isTrustedExectuable3(char *imagePath, char **argv, char **envp);
int lwip_trusted_untrustedCanExecuteAsTrusted(char *imagePath, char **argv, char **envp);
int lwip_trusted_untrustedExecuteAsTrusted(char *imagePath, char **argv, char **envp);

int lwip_trusted_canOpenLifor(const char *filePath);


#endif /* __LWIP_TRUSTED_H__ */

