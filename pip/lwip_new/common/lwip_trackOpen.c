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

#include "lwip_trackOpen.h"
#include "lwip_redirectHelper.h"
#include "lwip_utils.h"
#include "lwip_debug.h"
#include "strmap.h"
#include <stdio.h>
#include "ac.h"
#include "lwip_bufferManager.h"
#include <libgen.h>


static char *lwip_trackOpen_openLoggingPath = NULL;

// Store explictly specified name
StrMap *lwip_trackOpen_explicitSM = NULL;

// Store accessed filename
StrMap *lwip_trackOpen_accessedSM = NULL;


StrMap *lwip_trackOpen_untrustedSM = NULL;



void lwip_trackOpen_addUntrusted(char * untrustedStr) {
	if (lwip_trackOpen_untrustedSM == NULL) {
		lwip_trackOpen_untrustedSM = sm_new(20);
		if (lwip_trackOpen_untrustedSM == NULL) {
			LWIP_CRITICAL("Failed to create hash table");
			goto out;
		}
	}

	if (!sm_put(lwip_trackOpen_untrustedSM, untrustedStr, "untrusted"))
		LWIP_CRITICAL("Failed to add entry to hash table");
out:
	return;
}

int lwip_trackOpen_isUntrusted(char * testStr) {
	int rv = 0;
	if (lwip_trackOpen_untrustedSM == NULL)
		goto out;
	if (sm_exists(lwip_trackOpen_untrustedSM, testStr))
		rv = 1;
out:
	return rv;
}




AC_STRUCT *ac_node = NULL;
int ac_id = 0;
int ac_node_needPrepare = 0;



#define ac_add_str(_str) ac_add_string(ac_node, _str, strlen(_str), ac_id++)


char *lwip_trackOpen_getLoggingPath() {
	if (lwip_trackOpen_openLoggingPath == NULL) {
		lwip_trackOpen_openLoggingPath = lwip_bm_malloc(PATH_MAX);
		sprintf(lwip_trackOpen_openLoggingPath, LWIP_TRACKOPEN_DIR "/%s.openTrace", lwip_util_getProcessImagePath());
		lwip_createDirsIgnLast_with_permissions(lwip_trackOpen_openLoggingPath, LWIP_CF_TRUSTED_GROUP_GID, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
		int fd = open(lwip_trackOpen_openLoggingPath, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH|O_CREAT|O_EXCL);
		if (fd != -1) {
			fchown(fd, -1, LWIP_CF_TRUSTED_GROUP_GID);
			fchmod(fd, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
			close(fd);
		}
	}
	return lwip_trackOpen_openLoggingPath;
}

void lwip_trackOpen_loadExisting(){

	if (lwip_trackOpen_explicitSM != NULL) {
		sm_delete(lwip_trackOpen_explicitSM);
		sm_delete(lwip_trackOpen_accessedSM);
		lwip_trackOpen_explicitSM = NULL;
		lwip_trackOpen_accessedSM = NULL;
	}



	lwip_trackOpen_explicitSM = sm_new(20);

	if (lwip_trackOpen_explicitSM == NULL) {
		LWIP_CRITICAL("Failed to create hash table");
		goto out;
	}




	lwip_trackOpen_accessedSM = sm_new(50);
	if (lwip_trackOpen_accessedSM == NULL) {
		LWIP_CRITICAL("Failed to create hash table");
		sm_delete(lwip_trackOpen_explicitSM);
		lwip_trackOpen_explicitSM = NULL;
		goto out;
	}


#ifdef LWIP_SAVE_IMPLICIT_EXPLICIT_TO_FILE


	FILE *logFile = fopen(lwip_trackOpen_getLoggingPath(), "r");
	if (logFile == NULL) {
		if (errno != ENOENT)
			LWIP_CRITICAL("Cannot load the logging file (%s) errno: %d", lwip_trackOpen_getLoggingPath(), errno);
		goto out;
	}
	char *input = lwip_bm_malloc(PATH_MAX);

	while (fgets(input, PATH_MAX, logFile) != NULL) {
		input[strlen(input)-1] = 0;
		char mode[3];
		char *path = input + 6;
		switch (input[0]) {
		case 'E':
			if (!sm_put(lwip_trackOpen_explicitSM, path, "explicit"))
				LWIP_CRITICAL("Failed to add entry to hash table");
			break;
		case 'A':

			mode[0] = input[3];
			mode[1] = input[4];
			mode[2] = '\0';
			if (!sm_put(lwip_trackOpen_accessedSM, path, mode))
				LWIP_CRITICAL("Failed to add entry to hash table");
			break;
		//default:
			//LWIP_CRITICAL("Unexpected entry in the log file %s", path);
		}			
	}
	lwip_bm_free(input);
	fclose(logFile);
	LWIP_INFO("Loaded from DB from file: %s", lwip_trackOpen_getLoggingPath());
#endif

out:
	return;
}



void lwip_trackOpen_addToExplicitHash(char *path) {
}


#ifdef LWIP_SAVE_IMPLICIT_EXPLICIT_TO_FILE

#define lwip_trackOpen_log(format, args...) \
	do { \
		LWIP_CUSTOM_LOG(lwip_trackOpen_getLoggingPath(), format, ##args); \
	} while (0)

#else

#define lwip_trackOpen_log(format, args...)

#endif


void lwip_trackOpen_logExplict(char *path) {

	if (lwip_trackOpen_explicitSM == NULL)
		lwip_trackOpen_loadExisting();

	if (lwip_trackOpen_explicitSM == NULL)
		return;

	if (sm_exists(lwip_trackOpen_explicitSM, path))
		return;
	if (!sm_put(lwip_trackOpen_explicitSM, path, "explicit"))
		LWIP_CRITICAL("Failed to add entry to hash table");

	lwip_trackOpen_log("E:    %s", path);
}


void lwip_trackOpen_addExplict(char *path) {
	lwip_trackOpen_logExplict(path);
	if (ac_node == NULL)
		ac_node = ac_alloc();
	ac_add_str(path);

	//Add a dot between the basename and dirname
	char *buf = lwip_bm_malloc(PATH_MAX);

	int curPos = 0, lastSlash = -1;
	while (path[curPos] != '\0') {
		if (path[curPos] == '/') lastSlash = curPos;
		buf[curPos] = path[curPos];
		curPos++;
	}

	if (lastSlash > -1) {
		buf[curPos + 1] = '\0';
		while (buf[curPos-1] != '/') {
			buf[curPos] = buf[curPos - 1];
			curPos--;
		}
		buf[curPos] = '.';
		ac_add_str(buf);
	} else
		buf[curPos] = '\0';

	lwip_bm_free(buf);
	ac_node_needPrepare = 1;
}

void lwip_trackOpen_addImplict(char *path) {
	lwip_trackOpen_addExplict(path);
}

void lwip_trackOpen_addAccessed(char *path, int open_flags) {
	if (lwip_trackOpen_accessedSM == NULL)
		lwip_trackOpen_loadExisting();

	if (lwip_trackOpen_accessedSM == NULL)
		return;

	//FIXME: sm_exists will cause segfault in BSD. and it is not working properly

	char s_open_flags[3];
	open_flags &= 3; 
	if (sm_get(lwip_trackOpen_accessedSM, path, s_open_flags, sizeof(s_open_flags))) {
	//	lwip_trackOpen_log("#Existing: %s %s", s_open_flags, path);
		if (open_flags == O_RDONLY || open_flags == O_RDWR) {
			if (s_open_flags[0] != 'R')
				goto addString;
		}
		if (open_flags == O_WRONLY || open_flags == O_RDWR) {
			if (s_open_flags[1] != 'W')
				goto addString;
		}
		return;
	}

addString:
	if (open_flags == O_RDONLY || open_flags == O_RDWR)
		s_open_flags[0] = 'R';
	else
		s_open_flags[0] = ' ';
		
	if (open_flags == O_WRONLY || open_flags == O_RDWR)
		s_open_flags[1] = 'W';
	else
		s_open_flags[1] = ' ';

	s_open_flags[2] = '\0';

	if (!sm_put(lwip_trackOpen_accessedSM, path, s_open_flags))
		LWIP_CRITICAL("Failed to add entry to hash table");

//	LWIP_ASSERT1(sm_exists(lwip_trackOpen_accessedSM, path));

	lwip_trackOpen_log("A: %s %s", s_open_flags, path);

	return;
}

int lwip_trackOpen_testIsExplict(char *path, int open_flags) {

	lwip_trackOpen_addAccessed(path, open_flags);

/*	char *copystr = lwip_bm_malloc(PATH_MAX);
	strcpy(copystr, path);
	char *to_search = basename(copystr);
*/

	if (ac_node != NULL) {
		if (ac_node_needPrepare) {
			ac_prep(ac_node);
			ac_node_needPrepare = 0;
		}
		ac_search_init(ac_node, path, strlen(path));
//		ac_search_init(ac_node, to_search, strlen(path));
		
		char *s;
		int matchlen, matchid;
		int isExplict = 0;
		char *ac_buffer = lwip_bm_malloc(PATH_MAX);

		while ((s = ac_search(ac_node, &matchlen, &matchid)) != NULL) {
			if (matchlen <= 3)
				continue;
			strncpy(ac_buffer, s, matchlen);
			ac_buffer[matchlen] = 0;
			lwip_trackOpen_log("Log: opening of %s is regarded as explicit: %s", path, ac_buffer);
			isExplict = 1;
		}

		lwip_bm_free(ac_buffer);

//		if (!isExplict) {
//			lwip_trackOpen_log("Log: opening of %s is regarded as implicit", path);
//		}

	}
//	lwip_bm_free(copystr);

	return 0;
}
