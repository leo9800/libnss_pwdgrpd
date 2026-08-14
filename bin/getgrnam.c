#include <assert.h>
#include <nss.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include "nss-pwdgrpd.h"

int main(int argc, char *argv[])
{
	struct group grp;
	char buf[16384];
	enum nss_status r;
	int errnop;

	assert(argc == 2);
	r = _nss_pwdgrpd_getgrnam_r(argv[1], &grp, buf, 16384, &errnop);

	if (r == NSS_STATUS_SUCCESS) {
		printf("name=%s gid=%d\n", grp.gr_name, grp.gr_gid);
		for (char **m = grp.gr_mem; *m != NULL; m++) printf("\tmember: %s\n", *m);
	} else if (r == NSS_STATUS_NOTFOUND) {
		printf("not found ...\n");
	} else {
		printf("failure ...\n");
		return errnop;
	}
}