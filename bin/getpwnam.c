#include <assert.h>
#include <nss.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include "nss-pwdgrpd.h"

int main(int argc, char *argv[])
{
	struct passwd pwd;
	char buf[16384];
	enum nss_status r;
	int errnop;

	assert(argc == 2);
	r = _nss_pwdgrpd_getpwnam_r(argv[1], &pwd, buf, 16384, &errnop);

	if (r == NSS_STATUS_SUCCESS) {
		printf("name=%s uid=%d gid=%d shell=%s home=%s\n", pwd.pw_name, pwd.pw_uid, pwd.pw_gid, pwd.pw_shell, pwd.pw_dir);
	} else if (r == NSS_STATUS_NOTFOUND) {
		printf("not found ...\n");
	} else {
		printf("failure ...\n");
		return errnop;
	}
	return 0;
}