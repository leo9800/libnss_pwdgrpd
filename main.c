#include <assert.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include "nss-pwdgrpd.h"

int main(int argc, char *argv[])
{
	// struct passwd pwd;
	// struct group grp;
	// char buf[16384];
	// enum nss_status r;
	// int errnop;

	// assert(argc == 2);
	// r = _nss_pwdgrpd_getpwuid_r(atoi(argv[1]), &pwd, buf, 16384, &errnop);
	// // r = _nss_pwdgrpd_getgrnam_r(argv[1], &grp, buf, 16384, &errnop);

	// if (r == NSS_STATUS_SUCCESS) {
	// 	// printf("name=%s gid=%d\n", grp.gr_name, grp.gr_gid);
	// 	// for (char **m = grp.gr_mem; *m != NULL; m++)
	// 	// 	printf("member: %s\n", *m);
	// 	printf("name=%s uid=%d gid=%d shell=%s home=%s\n", pwd.pw_name, pwd.pw_uid, pwd.pw_gid, pwd.pw_shell, pwd.pw_dir);
	// } else if (r == NSS_STATUS_NOTFOUND) {
	// 	printf("not found ...\n");
	// } else {
	// 	printf("failure ...\n");
	// 	return errnop;
	// }

	assert(argc == 3);
	char *user = argv[1];
	gid_t group = atoi(argv[2]);
	enum nss_status r;
	int errnop;
	long int start, size, max;
	size = 10;
	max = 200;
	gid_t *groupsp = malloc(size * sizeof(gid_t));

	// groupsp[0] = (gid_t) 8888;
	start = 0;

	r = _nss_pwdgrpd_initgroups_dyn(user, group, &start, &size, &groupsp, max, &errnop);

	if (r == NSS_STATUS_SUCCESS) {
		printf("user=%s primary_gid=%d\n", user, group);
		for (int i = 0; i < start; i++)
			printf("gid: %d\n", groupsp[i]);
	} else if (r == NSS_STATUS_NOTFOUND) {
		printf("not found ...\n");
	} else {
		printf("failure ...\n");
		free(groupsp);
		return errnop;
	}

	free(groupsp);
	return 0;
}