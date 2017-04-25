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

#include <limits.h>
#include <unistd.h>
#include <string.h>
#include "lwip_in_utils.h"
#include "lwip_debug.h"
#include <stdlib.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <stdlib.h>


#define paraCheckingFn_signature (char *imagePath, char **argv, char **envp)

int defaultparaCheckingFn paraCheckingFn_signature;
int addUserCheckingFn paraCheckingFn_signature;

int lwip_in_trustedExe_python_gmenu_postinst paraCheckingFn_signature;

int dpkg_statoverrideCheckingFn paraCheckingFn_signature;


typedef struct trustedExecutable_paraCheckingFn {
	char imagePath[PATH_MAX];
	/* To check the parameters */
	int (*paraCheckingFn) paraCheckingFn_signature;
	/* Specific actions to take before exec, used in rudo */
	int (*actionFn) paraCheckingFn_signature;
} TrustedExe_Fn;

/*
//This suggests what can be executed as trusted, even the parents are untrusted.

static TrustedExe_Fn trustedExecutableList[] = {
	{.imagePath = "/sbin/ldconfig.real",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/mandb",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/fc-cache",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/update-desktop-database",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-fonts-scale",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-fonts-dir",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-mime",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/gtk-update-icon-cache",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/share/gnome-menus/update-gnome-menus-cache",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-alternatives",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/update-alternatives",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/defoma",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/mkfontscale",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-info-dir",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/var/lib/dpkg/info/ureadahead.postinst",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/update-mime-database.real",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/update-xmlcatalog",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/lib/libgtk2.0-0/gtk-update-icon-cache",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/install-docs",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/var/lib/dpkg/info/fontconfig.postinst",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/var/lib/dpkg/info/python-gmenu.postinst",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },


//Added after initial testing

	{.imagePath = "/usr/sbin/gconf-schemas",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/update-catalog",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/update-dictcommon-aspell",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/update-default-wordlist",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/update-default-ispell",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/adduser",
	 .paraCheckingFn = addUserCheckingFn,
	 .actionFn = NULL },
	
	{.imagePath = "/usr/sbin/addgroup",
	 .paraCheckingFn = addUserCheckingFn,
	 .actionFn = NULL },
	
	{.imagePath = "/usr/bin/dpkg-divert",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/bin/dpkg-query",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	//This program will modify and store what uid files should have
	{.imagePath = "/usr/bin/dpkg-statoverride",
	 .paraCheckingFn = dpkg_statoverrideCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/lwip/executables/dpkg/lwip_in_dpkg",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

//	{.imagePath = "/usr/share/debconf/frontend",
//	 .paraCheckingFn = defaultparaCheckingFn,
//	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/update-texmf",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },


#if 0
	{.imagePath = "/var/lib/dpkg/info/doc-base.postinst",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/bin/gconftool-2",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },


	{.imagePath = "/usr/bin/update-gconf-defaults",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },



	{.imagePath = "/usr/sbin/dpkg-preconfigure",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

//TODO: The followings should check the parameters passed in !!!

	{.imagePath = "/usr/sbin/useradd",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/groupadd",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/bin/chage",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },

	{.imagePath = "/usr/sbin/usermod",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
	{.imagePath = "/usr/sbin/userdel",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL },
#endif

	{.imagePath = "",
	 .paraCheckingFn = defaultparaCheckingFn,
	 .actionFn = NULL }
};


int defaultparaCheckingFn paraCheckingFn_signature {
	return 0;
}

int lwip_in_canExecuteAsTrusted paraCheckingFn_signature {
	int count = 0;

	if (imagePath == NULL)
		return 0;

	char resolvedPath[PATH_MAX];
	if (realpath(imagePath, resolvedPath) == NULL)
		return 0;

	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strcmp(trustedExecutableList[count].imagePath, resolvedPath) == 0) {
			if (trustedExecutableList[count].paraCheckingFn(resolvedPath, argv, envp)) {
				LWIP_CRITICAL("Exec %s is trusted, but env checking failed", imagePath);
				return 0;
			}
			LWIP_INFO("%s (%s) can be executed as trusted with env checking passed", imagePath, resolvedPath);
			return 1;
		}
		count++;
	}
	return 0;
}

		
int lwip_in_ExecuteAsTrusted paraCheckingFn_signature {
	int count = 0;

	if (imagePath == NULL)
		return 0;

	char resolvedPath[PATH_MAX];
	if (realpath(imagePath, resolvedPath) == NULL)
		return 0;

	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strcmp(trustedExecutableList[count].imagePath, resolvedPath) == 0) {
			if (trustedExecutableList[count].paraCheckingFn(resolvedPath, argv, envp)) {
				LWIP_CRITICAL("Exec %s is trusted, but env checking failed", imagePath);
				return 0;
			}
			LWIP_INFO("%s (%s) can be executed as trusted with env checking passed", imagePath, resolvedPath);
			if (trustedExecutableList[count].actionFn != NULL)
				trustedExecutableList[count].actionFn(imagePath, argv, envp);
			//This is required for scripts, where image path will be changed to dash
			setenv("LWIP_TRUSTED_ASIF", resolvedPath, 1);
			execv(imagePath, argv);
			return 1;
		}
		count++;
	}
	return 0;


}


int lwip_in_checkParameterList(char **argv, char **parameter_list) {
	int count = 0;
	int rv = -1;
	while (parameter_list[count] != NULL) {
		if (argv[count] == NULL)
			goto out;
		if (strcmp(parameter_list[count], argv[count]) != 0)
			goto out;
		count++;
	}
	if (parameter_list[count] == argv[count])
		rv = 0;
out:
	return rv;

}


int lwip_in_trustedExe_python_gmenu_postinst paraCheckingFn_signature {
	char *parameter_list[] = { 
		"/var/lib/dpkg/info/python-gmenu.postinst",
		"triggered", 
		"/usr/share/applications",
		NULL };
	return lwip_in_checkParameterList(argv, parameter_list);
}


int addUserCheckingFn paraCheckingFn_signature {
	if (lwip_util_stringInArray("--system", (const char * const *)argv)) {
		LWIP_IN_TRACE_MSG("Violation: Will add user in system group not allowed (but not enforced)");
		return -1;
	}
	return 0;
}

int addGroupCheckingFn paraCheckingFn_signature {
	if (lwip_util_stringInArray("--system", (const char * const *)argv)) {
		LWIP_IN_TRACE_MSG("Violation: Will add user in system group not allowed (but not enforced)");
		return -1;
	}
	return 0;
}

int dpkg_statoverrideCheckingFn paraCheckingFn_signature {
	int i = 0;
	while (argv[i] != NULL) {
		if (strcmp(argv[i], "--add") == 0) {
			if (argv[i+1] == NULL || argv[i+2] == NULL || argv[i+3] == NULL || argv[i+4] == NULL)
				return -1;

			mode_t mode = strtol(argv[i+3], NULL, 8);
			char *file = argv[i+4];

			struct passwd *passwdEntry = getpwnam(argv[i+1]);
 			if (passwdEntry == NULL) {
				LWIP_IN_TRACE_MSG("Violation:, Making file %s to be owned by a non-existence user %s", file, argv[i+1]);
				return -1;
			}
			uid_t uid = passwdEntry->pw_uid;

			struct group *groupEntry = getgrnam(argv[i+2]);
			if (groupEntry == NULL) {
				LWIP_IN_TRACE_MSG("Violation:, Making file %s to be owned by a non-existence group %s", file, argv[i+2]);
				return -1;
			}
			gid_t gid = groupEntry->gr_gid;

			if ((mode & S_ISUID) && (uid == 0)) {
				LWIP_IN_TRACE_MSG("Violation: Making file %s to be root setuid, not allowed", file);
				return -1;
			}
			if ((mode & S_ISGID) && (gid == 0)) {
				LWIP_IN_TRACE_MSG("Violation: Making file %s to be root setgid, not allowed", file);
				return -1;
			}

			return 0;
		}
		i++;
	}
	return 0;

}


//get the package name from .deb filename
char *lwip_in_deb2packageName(char *debPath, char *buffer) {

	char command[PATH_MAX];
	snprintf(command, PATH_MAX, LWIP_TRUSTED " dpkg-deb -f %s package", debPath);
        FILE* file = popen(command, "re");

	if (fgets(command, PATH_MAX, file) == NULL)
		buffer[0] = 0;
	else {
		sscanf(command, "%[^ \n]", buffer);
	}

	pclose(file);
	return buffer;
}


*/

