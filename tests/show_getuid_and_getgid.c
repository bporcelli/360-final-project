#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "test-util.h"
#include "common.h"
#include "level.h"

/**
 * Transparency demonstration.
 *
 * Shows that getuid()/getgid() return the trusted user id and trusted
 * group id, respectively, when the process is running with the untrusted
 * user id.
 */
int main(int argc, char **argv) {
	uid_t uid = geteuid();
	int ulevel = sip_uid_to_level(uid);

	printf("Trusted UID = %d, Trusted GID = %d, Untrusted UID = %d.\n",
		   SIP_REAL_USERID, SIP_TRUSTED_GROUP_GID, SIP_UNTRUSTED_USERID);

	printf("Running with UID %d (%s)\n", uid, level_to_string(ulevel));

	printf("Result of getuid(): %d\n", getuid());
	printf("Result of getgid(): %d\n", getgid());
}