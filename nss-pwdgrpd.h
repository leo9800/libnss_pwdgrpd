#ifndef _NSS_PWDGRPD_H
#define _NSS_PWDGRPD_H

#include <nss.h>

enum nss_status _nss_pwdgrpd_getpwnam_r(const char *, struct passwd *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_getpwuid_r(const uid_t, struct passwd *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_getgrnam_r(const char *, struct group *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_getgrgid_r(const gid_t, struct group *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_initgroups_dyn(const char *, gid_t, long int *, long int *, gid_t **, long int, int *);
enum nss_status _nss_pwdgrpd_getpwent_r(struct passwd *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_setpwent(void);
enum nss_status _nss_pwdgrpd_endpwent(void);
enum nss_status _nss_pwdgrpd_getgrent_r(struct group *, char *, size_t, int *);
enum nss_status _nss_pwdgrpd_setgrent(void);
enum nss_status _nss_pwdgrpd_endgrent(void);

#endif
