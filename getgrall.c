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

	do {
		r = _nss_pwdgrpd_getgrent_r(&grp, buf, 16384, &errnop);
		if (r == NSS_STATUS_SUCCESS) {
			printf("name=%s gid=%d\n", grp.gr_name, grp.gr_gid);
			for (char **m = grp.gr_mem; *m != NULL; m++) printf("\tmember: %s\n", *m);
		}
	} while (r == NSS_STATUS_SUCCESS);

	_nss_pwdgrpd_endgrent();
	return 0;
}