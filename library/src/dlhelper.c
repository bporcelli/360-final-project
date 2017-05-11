#include <dlfcn.h>
#include <stdlib.h>
#include "dlhelper.h"
#include "logger.h"

static void *dlhandle = NULL;

void *sip_find_sym(const char *symbol) {
	if (dlhandle == NULL) {
		dlhandle = dlopen("libc.so.6", RTLD_LAZY);

		if (dlhandle == NULL) { /* Fatal error */
			sip_error("Failed to open libc.so.6. Aborting.\n");
			exit(1);
		}
	}

	return dlsym(dlhandle, symbol);
}
