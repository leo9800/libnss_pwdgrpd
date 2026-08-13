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
		for (int i = 0; i < start; i++) printf("\tgid: %d\n", groupsp[i]);
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