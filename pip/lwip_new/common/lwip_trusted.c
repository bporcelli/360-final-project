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

#include "lwip_utils.h"
#include <string.h>
#include <limits.h>
#include "lwip_trusted.h"
#include <stdlib.h>
#include "lwip_debug.h"
#include "lwip_level.h"

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "lwip_in_utils.h"
#include "lwip_bufferManager.h"

// The list suggests what is trusted for the executables

int trustedContextFn_alwaysTrusted trustedContext_signature;
int trustedContextFn_unchanged trustedContext_signature;
int trustedContextFn_dpkg_statoverride trustedContext_signature;
int trustedContextFn_addUser trustedContext_signature;
int trustedContextFn_addGroup trustedContext_signature;
int trustedContextFn_reportAsViolation trustedContext_signature;
int trustedContextFn_useradd trustedContext_signature;
int trustedContextFn_usermod trustedContext_signature;
int trustedContextFn_onlySystemDBus trustedContext_signature;

#define NO_INTERCEPTION_ON_TRUSTED_CONTEXT 1


int inTrustedContext(){
	uid_t uid = getuid();
	if (level_isUntrustedUid(uid))
		return 0;
	return 1;
}

static TrustedExe_CS trustedExecutableList[] = {

	/**************************************************
	 * Will execute without changing its integrity level 
	 **************************************************/
	{.imagePath = "/lwip/executables/dpkg/dpkg_original",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dpkg/",
		"/usr/lib/mime/packages/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_unchanged
        },

	{.imagePath = "/usr/share/debconf/frontend",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/cache/debconf/config.dat",
		"/var/lib/dpkg/info/",
		"/var/cache/debconf/templates.dat",
		NULL
	   },
	  .trustedContextFn = trustedContextFn_unchanged
        },

	/*
	  Description: ??
	  From package: tex ??
	*/
        {.imagePath = "/usr/bin/update-fontlang",
         .inheritable_trust = 1, /*It is a bash script*/
         .openWithoutDowngradingDir = (const char * const []){
                "/var/lib/tex-common/fmtutil-cnf/",
                NULL
            },
          .trustedContextFn = trustedContextFn_unchanged
        },

	/*
	  Description: a tool to query the dpkg database
	  Justification: No change in integrity, but to allow read-down
			 on specified directory.
	*/
	{.imagePath = "/usr/bin/dpkg-query",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dpkg/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_unchanged
        },


	{.imagePath = "/bin/su",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_reportAsViolation
        },


	/**************************************************
	 * Policies required
	 **************************************************/
	{.imagePath = "/usr/bin/dpkg-statoverride",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
	   },
	  .trustedContextFn = trustedContextFn_dpkg_statoverride
	 },

	{.imagePath = "/usr/sbin/adduser",
	 .inheritable_trust = 1, /* Perl + other programs */
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_addUser
        },

        {.imagePath = "/usr/sbin/useradd",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_useradd
        },

	 {.imagePath = "/usr/sbin/usermod",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_usermod
        },

	/* 
	   Justification: Trust only if it is a system DBus because
			  system DBus will be running with a non-root 
			  uid
	*/
        {.imagePath = "/bin/dbus-daemon",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_onlySystemDBus
        },


	/**************************************************
	 * Always executed as high integrity, but no read-down
	 **************************************************/

	/*
	  Description: a way of forcing dpkg(1) not to install a file 
		       into its location, but to a diverted location
	  Justification: Require justification
	*/
	{.imagePath = "/usr/bin/dpkg-divert",
	 .inheritable_trust = 1, /* Perl */
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/* 
	   Description: configure dynamic linker run-time bindings
	   Parameters: Usually do not take arguments
	   Justification: ldconfig.real does not depend on library. 
 			  No read-down cannot be enforced. We can only
			  trust it.
	*/
	{.imagePath = "/sbin/ldconfig.real",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: XML catalog is a document describing a mapping 
		       between external entity references and 
		       locally-cached equivalents. This tool is to 
		       update the xml catalog typically located at /etc/xml
	*/
	{.imagePath = "/usr/sbin/update-xmlcatalog",
	 .inheritable_trust = 1, /* Perl */
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: Similar to update-xmlcatalog, but to Standard 
		       Generalized Markup Language (SGML) catalog file
		       located at /etc/sgml
	*/
	{.imagePath = "/usr/sbin/update-catalog",
	 .inheritable_trust = 1, /* Perl */
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: maintain symbolic links determining default commands
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/update-alternatives",
	 .inheritable_trust = 1, /*perl script*/
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: gio-querymodules creates a giomodule.cache file in the 
		       listed directories. This file lists the implemented 
		       extension points for each module that has been found. 
		       It is used by GIO at runtime to avoid opening all modules 
		       just to find out which extension points they are implementing.
	  Parameters: /usr/lib/gio/modules
	  Justification: No-read-down is involved. Just to allow the creation of
			 the cache file to be of high integrity.
	*/
        {.imagePath = "/usr/bin/gio-querymodules",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_alwaysTrusted
        },



	/**************************************************
	 * Always executed as high integrity, with read-down exception
	 **************************************************/
        {.imagePath = "/usr/bin/mandb",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		 "/usr/man",
		 "/usr/share/man",
		 "/usr/local/man",
		 "/usr/local/share/man",
		 "/usr/X11R6/man",
		 "/opt/man",
		 "/usr/lib/", /* /usr/lib/mpich-mpd/man/man1/ */
		 NULL
          },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: register gconf schemas with the gconf database
		       example of gconf schema:
		       <schema>
		         <applyto>/desktop/gnome/interface/font_name</applyto>
		         <key>/schemas/desktop/gnome/interface/font_name</key>
		         <owner>gnome</owner>
		         <type>string</type>
		         <default>Sans 10</default>
		         <locale name="C">
		           <short>Default font</short>
		           <long>Name of the default font used by gtk+.</long>
		         </locale>
		       </schema>
	               GConf can be a DBus daemon which provides user perferences
	  Justification: XXX
	*/
	{.imagePath = "/usr/sbin/gconf-schemas",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/gconf/schemas/",
		"/usr/lib/python2.6/dist-packages/python-support.pth",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: GNOME menu
	*/
        {.imagePath = "/var/lib/dpkg/info/python-gmenu.postinst",
	 .inheritable_trust = 1, /*shell script*/
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/applications/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: (re-)creates the index of available documentation 
			in info format (the file /usr/share/info/dir) 
			which is usually presented by info browsers on 
			startup.
	  Parameters: (Optional) directory
	  Justification: Same as mandb
	*/
	{.imagePath = "/usr/sbin/update-info-dir",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/info/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: manage online Debian documentation
	  Parameters: document to install/remove/...
	  Justification: Same as mandb?
	*/
	{.imagePath = "/usr/sbin/install-docs",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/doc-base/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: is responsible for updating the shared 
		   	mime-info cache (e.g., at /usr/share/mime-info/)
	  Parameters: directory to update the mime-info cache
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/update-mime-database.real",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/mime/packages/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: a wrapper script for updating the icon 
			caches in a list of directories
	*/
	{.imagePath = "/usr/sbin/update-icon-caches",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/icons/",
		"/usr/share/bkchem/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: creates mmap()able cache files for icon themes
	*/
	{.imagePath = "/usr/lib/libgtk2.0-0/gtk-update-icon-cache",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: byte-compile python modules
	  Justification: FIXME
	*/
	{.imagePath = "/usr/sbin/update-python-modules",
	 .inheritable_trust = 1, /* Python */
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/lib/",
		"/usr/share/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: a tool to explicitely activate triggers
	  Justification: FIXME
	*/
	{.imagePath = "/usr/bin/dpkg-trigger",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dpkg/triggers/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

        /* 
	  Description: Build cache database of MIME types handled 
			by desktop files 
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/update-desktop-database",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/",
		"/etc/xdg/autostart/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	{.imagePath = "/usr/sbin/update-fonts-scale", //Will write /usr/share/fonts/X11/Type1/fonts.scale
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/etc/X11/fonts/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },



	{.imagePath = "/usr/lib/openoffice/program/unopkg.bin", //will modify files in "/var/spool/openoffice/uno_packages/cache/",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
		"/usr/lib/openoffice/share/extension/install/",
                NULL
            },
          .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	{.imagePath = "/usr/share/gnome-menus/update-gnome-menus-cache",
         .inheritable_trust = 1, /* python */
         .openWithoutDowngradingDir = (const char * const []){
                "/usr/share/",
		"/usr/lib/", /* /usr/lib/wx/python/wx2.8.pth */
		"/etc/xdg/autostart/",
                NULL
            },
          .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/* 
	  Description: Reads the system default from the debconf 
			database and set default links in /etc/dictionaries-common 
			pointing to the appropriate files in /usr/share/dict/.
			If option --rebuild is given, rebuilds the /var/cache/dictionaries-common/wordlist.db
			from the files in /var/lib/dictionaries-common/wordlist
	  Justification: XXX
	*/
	{.imagePath = "/usr/sbin/update-default-wordlist",
	 .inheritable_trust = 1, /*perl script*/
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dictionaries-common/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: Debian Font Manager, a framework for automatic 
			font configuration
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/defoma",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/etc/defoma/hints/",
		"/usr/share/defoma/scripts/", /* for defoma-app */
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: generating defaults used by GConf from
			the files found in /usr/share/gconf/defaults
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/update-gconf-defaults",
	 .inheritable_trust = 1,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/gconf/defaults/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: fc-cache scans the font directories on the system 
			and builds font information cache files for 
			applications using fontconfig for their font 
			handling.
	  Justification: XXX
	*/
	{.imagePath = "/usr/bin/fc-cache",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/",
		"/etc/fonts/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	{.imagePath = "/usr/bin/mkfontscale",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: create an index of X font files in a directory
	*/
	{.imagePath = "/usr/bin/mkfontdir",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/share/fonts/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: Rebuild aspell database and emacsen stuff
	  From package: dictionaries-common
	  Parameters: takes no arguments
	*/
	{.imagePath = "/usr/sbin/update-dictcommon-aspell",
	 .inheritable_trust = 1, /* Perl script */
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dictionaries-common/aspell/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/* 
          Description: Autobuilding aspell hash files for some dicts
	  From package: dictionaries-common
	  Parameters: takes no arguments
	*/
	{.imagePath = "/usr/sbin/aspell-autobuildhash",
	 .inheritable_trust = 1, /* Perl script */
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dictionaries-common/aspell/",
		"/usr/lib/aspell/",
		"/var/lib/aspell/",
		"/usr/share/aspell/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	//This is not really required, but without this, sometime may result in infinite loop.
	{.imagePath = "/usr/bin/apt-get",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dpkg/lock",
		"/var/lib/apt/extended_states",
		"/var/lib/dpkg/status",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: updates the /etc/mailcap file to reflect mime 
			information changed by a Debian package during 
			installation or removal
	*/
	{.imagePath = "/usr/sbin/update-mime",
	 .inheritable_trust = 1, /*It is a perl script*/
	 .openWithoutDowngradingDir = (const char * const []){
		"/usr/lib/mime/packages/",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	/*
	  Description: assembles a fonts.alias file in an X font directory 
			using one or more alias files found in a subdirectory 
			of /etc/X11/fonts/
	*/
        {.imagePath = "/usr/sbin/update-fonts-alias",
         .inheritable_trust = 1, /*It is a bash script*/
         .openWithoutDowngradingDir = (const char * const []){
		"/etc/X11/fonts/",
                NULL
            },
          .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	{.imagePath = "/usr/share/software-center/software-center",
	 .inheritable_trust = 1, /* Python */
	 .openWithoutDowngradingDir = (const char * const []){
		"/var/lib/dpkg/status",
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        },

	
	/**************************************************
	 * Should not be allowed to execute during 
	 * installation of untrusted packages
	 **************************************************/

	/*
	  Description: Dynamic Kernel Module Support Framework (DKMS) is a 
			framework designed to allow individual kernel modules 
			to be upgraded without changing the whole kernel. 
			It is also very easy to rebuild modules as you upgrade 
			kernels
	  From package: dkms
	*/
        {.imagePath = "/usr/sbin/dkms",
         .inheritable_trust = 1, /*It is a bash script*/
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_reportAsViolation
        },

	/*
	  Description: generate an initramfs image
	*/
        {.imagePath = "/usr/sbin/update-initramfs",
         .inheritable_trust = 1, /*It is a bash script*/
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_reportAsViolation
        },

	/*
	  Description: depmod creates a list of module dependencies by 
			reading each module under /lib/modules/version 
			and determining what symbols it exports and what
		        symbols it needs
	*/
        {.imagePath = "/sbin/depmod",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_reportAsViolation
        },


	{.imagePath = "/usr/sbin/update-rc.d",
         .inheritable_trust = 0,
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_reportAsViolation
        },

        {.imagePath = "/usr/sbin/update-grub",
         .inheritable_trust = 1, /*It is a bash script*/
         .openWithoutDowngradingDir = (const char * const []){
                NULL
            },
          .trustedContextFn = trustedContextFn_reportAsViolation
        },




        {.imagePath = "",
	 .inheritable_trust = 0,
	 .openWithoutDowngradingDir = (const char * const []){
		NULL
            },
	  .trustedContextFn = trustedContextFn_alwaysTrusted
        }
};

static int isTrustedExecutable = -1;
static char **openWithoutDowngradingDir = NULL;


int lwip_trusted_isTrustedExecutablePath(char *path) {
	int rv = 0;

	int count = 0;
	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strncmp(path, trustedExecutableList[count].imagePath, PATH_MAX) == 0) {
			rv = 1;
			goto out;
		}
		count++;
	}


out:
	return rv;
}


int lwip_trusted_isTrustedExectuable() {

	if (isTrustedExecutable != -1)
		return isTrustedExecutable;

	char *processImagePath = lwip_util_getProcessImagePath();
	int count = 0;
	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strncmp(processImagePath, trustedExecutableList[count].imagePath, PATH_MAX) == 0) {
			openWithoutDowngradingDir = (char **)trustedExecutableList[count].openWithoutDowngradingDir;
			isTrustedExecutable = 1;
			if (trustedExecutableList[count].inheritable_trust)
				setenv("LWIP_TRUSTED_ASIF", processImagePath, 1);
			else
				unsetenv("LWIP_TRUSTED_ASIF");
			goto out;
		}
		count++;
	}

	processImagePath = getenv("LWIP_TRUSTED_ASIF");
	if (processImagePath != NULL) {
		count = 0;
		while (trustedExecutableList[count].imagePath[0] != 0) {
			if (strncmp(processImagePath, trustedExecutableList[count].imagePath, PATH_MAX) == 0) {
				openWithoutDowngradingDir = (char **)trustedExecutableList[count].openWithoutDowngradingDir;
				isTrustedExecutable = 1;
				goto out;
			}
			count++;
		}
	}

	openWithoutDowngradingDir = NULL;
	isTrustedExecutable = 0;
out:
	if (isTrustedExecutable)
		LWIP_INFO("Process is a trusted-confined trusted executable");
	else
		LWIP_INFO("Process is not a trusted-confined trusted executable");

	return isTrustedExecutable;
}

int lwip_trusted_canOpenLifor(const char *filePath) {
	if (!lwip_trusted_isTrustedExectuable() || openWithoutDowngradingDir == NULL)
		return 0;
	
	return lwip_util_stringInPrefixArray(filePath, (const char * const *)openWithoutDowngradingDir);

}


int trustedContextFn_alwaysTrusted trustedContext_signature {
	return 0;
}

int trustedContextFn_unchanged trustedContext_signature {
	uid_t uid = getuid();
	if (level_isUntrustedUid(uid))
		return -1;
	return 0;
}

int trustedContextFn_dpkg_statoverride trustedContext_signature {
	int i = 0;
	while (argv[i] != NULL) {
		if (strcmp(argv[i], "--add") == 0) {

			int j;
			for (j=i+1; argv[j] != NULL; j++) {
				if (argv[j][0] != '-') {
					i = j-1;
					break;
				}
			}

			if (argv[i+1] == NULL || argv[i+2] == NULL || argv[i+3] == NULL || argv[i+4] == NULL)
				return -1;

			mode_t mode = strtol(argv[i+3], NULL, 8);
			char *file = argv[i+4];

			struct passwd *passwdEntry = getpwnam(argv[i+1]);
 			if (passwdEntry == NULL) {
				LWIP_IN_TRACE_MSG("Violation: Making file %s to be owned by a non-existence user %s", file, argv[i+1]);
				return -1;
			}
			uid_t uid = passwdEntry->pw_uid;

			struct group *groupEntry = getgrnam(argv[i+2]);
			if (groupEntry == NULL) {
				LWIP_IN_TRACE_MSG("Violation: Making file %s to be owned by a non-existence group %s", file, argv[i+2]);
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

			if ((mode & S_ISUID)) {
				LWIP_IN_TRACE_MSG("Info: Making file %s to be non-root setuid with uid %d", file, uid);
			}

			if ((mode & S_ISGID)) {
				LWIP_IN_TRACE_MSG("Info: Making file %s to be non-root setgid with gid %d", file, gid);
			}

			return 0;
		}
		i++;
	}
	return 0;

}

char *getLastStr(char **strArray) {
	int count = 0;
	while (strArray[count] != NULL)
		count++;
	if (count == 0)
		return NULL;
	return strArray[count-1];
}

int trustedContextFn_addUser trustedContext_signature {
	LWIP_IN_TRACE_MSG("Information: Allow adding user!");
	return 0;
	if (lwip_util_stringInArray("--system", (const char * const *)argv)) {
		LWIP_IN_TRACE_MSG("Violation: Will add user in system group not allowed (%s)", getLastStr(argv));
		return -1;
	}
	return 0;
}

int trustedContextFn_addGroup trustedContext_signature {
	LWIP_IN_TRACE_MSG("Information: Allow adding group!");
	return 0;
	if (lwip_util_stringInArray("--system", (const char * const *)argv)) {
		LWIP_IN_TRACE_MSG("Violation: Will add user in system group not allowed (%s)", getLastStr(argv));
		return -1;
	}
	return 0;
}





int lwip_trusted_untrustedCanExecuteAsTrusted(char *imagePath, char **argv, char **envp) {

	int count = 0;
	int rv = 0;

	if (imagePath == NULL)
		return rv;

	char *resolvedPath = lwip_bm_malloc(PATH_MAX);
	if (realpath(imagePath, resolvedPath) == NULL)
		goto out;

	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strcmp(trustedExecutableList[count].imagePath, resolvedPath) == 0) {
			if (trustedExecutableList[count].trustedContextFn(resolvedPath, argv, envp)) {
				LWIP_CRITICAL("Executable %s is trusted, but env checking failed", imagePath);
				goto out;
			}
			LWIP_INFO("%s (%s) can be executed as trusted with env checking passed", imagePath, resolvedPath);
			rv = 1;
			goto out;
		}
		count++;
	}
out:
	lwip_bm_free(resolvedPath);
	return rv;

}

int lwip_trusted_untrustedExecuteAsTrusted(char *imagePath, char **argv, char **envp) {
	int count = 0;
	int rv = 0;

	if (imagePath == NULL)
		return rv;

	char *resolvedPath = lwip_bm_malloc(PATH_MAX);;
	if (realpath(imagePath, resolvedPath) == NULL)
		goto out;

	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strcmp(trustedExecutableList[count].imagePath, resolvedPath) == 0) {
			if (trustedExecutableList[count].trustedContextFn(resolvedPath, argv, envp)) {
				LWIP_CRITICAL("Executable %s is trusted, but env checking failed", imagePath);
				goto out;
			}
			LWIP_INFO("%s (%s) can be executed as trusted with env checking passed", imagePath, resolvedPath);
			//Set the TRUSTED_AS_IF if it is inheritable
			setenv("LWIP_TRUSTED_ASIF", resolvedPath, 1);
			execv(imagePath, argv);
			LWIP_CRITICAL("Failed to exec image at path: %s", imagePath);
			rv = 1;
			goto out;
		}
		count++;
	}
	LWIP_CRITICAL("%s is not a trust confined process!!!, may execve as untrusted!", imagePath);
out:
	lwip_bm_free(resolvedPath);
	return rv;

}

int lwip_trusted_isTrustedExectuable3(char *imagePath, char **argv, char **envp) {

	int count = 0;
	int rv = 0;

	if (imagePath == NULL)
		return rv;

	char *resolvedPath = lwip_bm_malloc(PATH_MAX);;
	if (realpath(imagePath, resolvedPath) == NULL)
		goto out;

	while (trustedExecutableList[count].imagePath[0] != 0) {
		if (strcmp(trustedExecutableList[count].imagePath, resolvedPath) == 0) {
			rv = 1;
			goto out;
		}
		count++;
	}
out:
	lwip_bm_free(resolvedPath);
	return rv;
}


int trustedContextFn_reportAsViolation trustedContext_signature {
	LWIP_IN_TRACE_MSG("Violation: %s will be invoked which is not supposed to be supported with untrusted packages", imagePath);
	return -1;
}

int trustedContextFn_usermod trustedContext_signature {
	LWIP_IN_TRACE_MSG("Information: Allow modifying user information");
	return 0;
}

int trustedContextFn_useradd trustedContext_signature {
	int i = 0;
	LWIP_IN_TRACE_MSG("Information: Allow adding user!");
	return 0;
	while (argv[i] != NULL) {
		if (strcmp(argv[i], "--system") == 0 || strcmp(argv[i], "-r") == 0) {
			LWIP_IN_TRACE_MSG("Violation: will create system account");
			return -1;
		}

		if (strcmp(argv[i], "--uid") == 0 || strcmp(argv[i], "-u") == 0) {
			if (argv[i+1] == NULL)
				return -1;
			if (atoi(argv[i+1]) < 999) {
				LWIP_IN_TRACE_MSG("Violation: Will add user with uid less then 999");
				return -1;
			}
		}
		i++;
	}

	return 0;

}


int trustedContextFn_onlySystemDBus trustedContext_signature {
	if (lwip_util_stringInArray("--system", (const char * const *)argv)) {
		return 0;
	}
	//Session Dbus should not be started as root because it does not setuid to non-root user!!
	return -1;

}


