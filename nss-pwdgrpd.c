#include <asm-generic/errno-base.h>
#include <json-c/json.h>
#include <curl/curl.h>
#include <json-c/json_object.h>
#include <json-c/json_types.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include "nss-pwdgrpd.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#ifndef PWDGRPD_API_ENDPOINT
#define PWDGRPD_API_ENDPOINT "http://localhost:8000"
#endif

static struct json_object *__pwdgrpd_pwall = NULL;
static struct json_object *__pwdgrpd_grall = NULL;
off_t __pwdgrpd_pwall_off = -1;
off_t __pwdgrpd_grall_off = -1;

static size_t curl_write_cb(void *, size_t, size_t, void *);
static inline char *safe_bufcpy(const char *, char **, const char *, const size_t);
static inline enum nss_status __pwdgrpd_pw(const char *, struct passwd *, char *, size_t, int *);
static inline enum nss_status __pwdgrpd_gr(const char *, struct group *, char *, size_t, int *);
static inline enum nss_status __pwdgrpd_parse_pw_json(const struct json_object *, struct passwd *, char *, size_t, int *);
static inline enum nss_status __pwdgrpd_parse_gr_json(const struct json_object *, struct group *, char *, size_t, int *);

struct binary_string {
	size_t size;
	char *payload;
};

enum nss_status _nss_pwdgrpd_getpwnam_r(
	const char *name,
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[1024];
	snprintf(url, sizeof(url), PWDGRPD_API_ENDPOINT"/getpwnam/%s?t=json", name);
	return __pwdgrpd_pw(url, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_getpwuid_r(
	const uid_t uid,
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[1024];
	snprintf(url, sizeof(url), PWDGRPD_API_ENDPOINT"/getpwuid/%d?t=json", uid);
	return __pwdgrpd_pw(url, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_getgrnam_r(
	const char *name,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[1024];
	snprintf(url, sizeof(url), PWDGRPD_API_ENDPOINT"/getgrnam/%s?t=json", name);
	return __pwdgrpd_gr(url, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_getgrgid_r(
	const gid_t gid,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[1024];
	snprintf(url, sizeof(url), PWDGRPD_API_ENDPOINT"/getgrgid/%d?t=json", gid);
	return __pwdgrpd_gr(url, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_initgroups_dyn(
	const char *user,
	gid_t group,
	long int *start,
	long int *size,
	gid_t **groupsp,
	long int limit,
	int *errnop
)
{
	int http_status;
	char url[1024];

	snprintf(url, 1024, PWDGRPD_API_ENDPOINT"/initgroups/%s?t=json&b=gid", user);
	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		curl_global_cleanup();
		*errnop = ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}

	struct binary_string http_res = {.payload = malloc(1), .size = 0};
	http_res.payload[0] = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_res);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		free(http_res.payload);
		*errnop = EIO;
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 403) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 404) {
		free(http_res.payload);
		return NSS_STATUS_NOTFOUND;
	}

	if (http_status != 200) {
		free(http_res.payload);
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	struct json_object *json = json_tokener_parse(http_res.payload);
	free(http_res.payload);

	if (!json) {
		*errnop = EINVAL;
		return NSS_STATUS_TRYAGAIN;
	}

	if (json_object_get_type(json) != json_type_array) {
		json_object_put(json);
		*errnop = EINVAL;
		return NSS_STATUS_TRYAGAIN;
	}

	size_t ngids = json_object_array_length(json);

	if (*size - *start <= ngids + 1) { // 1 gid specified in param + other retrieved by API
		// expand required ...
		size_t newsize = MIN(*size * 2, limit);
		gid_t *new_groupsp = realloc(*groupsp, newsize);
		if (new_groupsp == NULL) {
			json_object_put(json);
			*errnop = ENOMEM;
			return NSS_STATUS_TRYAGAIN;
		}
		*groupsp = new_groupsp;
	}

	(*groupsp)[*start] = group;
	*start += 1;

	for (int i = 0; i < ngids; i++) {
		struct json_object *item = json_object_array_get_idx(json, i);
		(*groupsp)[*start] = (gid_t) json_object_get_int(item);
		*start += 1;
	}

	json_object_put(json);
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_getpwent_r(
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	if (__pwdgrpd_pwall_off == -1) {
		_nss_pwdgrpd_setpwent();
		if (__pwdgrpd_pwall_off == -1) {
			*errnop = EIO;
			return NSS_STATUS_UNAVAIL;
		}
	}
	size_t npwds = json_object_array_length(__pwdgrpd_pwall);
	if (__pwdgrpd_grall_off >= npwds)
		return NSS_STATUS_NOTFOUND;
	struct json_object *j_pwd;
	if (!json_object_array_get_idx(__pwdgrpd_pwall, __pwdgrpd_pwall_off)) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}
	return __pwdgrpd_parse_pw_json(j_pwd, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_setpwent()
{
	int http_status;
	char url[1024];

	snprintf(url, 1024, PWDGRPD_API_ENDPOINT"/getpwall?t=json");
	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		curl_global_cleanup();
		return NSS_STATUS_UNAVAIL;
	}

	struct binary_string http_res = {.payload = malloc(1), .size = 0};
	http_res.payload[0] = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_res);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 403) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status != 200) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	__pwdgrpd_pwall = json_tokener_parse(http_res.payload);
	free(http_res.payload);

	if (!__pwdgrpd_pwall) {
		__pwdgrpd_pwall_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	if (json_object_get_type(__pwdgrpd_pwall) != json_type_array) {
		json_object_put(__pwdgrpd_pwall);
		__pwdgrpd_pwall = NULL;
		__pwdgrpd_pwall_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	__pwdgrpd_pwall_off = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_endpwent()
{
	if (__pwdgrpd_pwall) json_object_put(__pwdgrpd_pwall);
	__pwdgrpd_pwall = NULL;
	__pwdgrpd_pwall_off = -1;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_getgrent_r(
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	if (__pwdgrpd_grall_off == -1) {
		_nss_pwdgrpd_setgrent();
		if (__pwdgrpd_grall_off == -1) {
			*errnop = EIO;
			return NSS_STATUS_UNAVAIL;
		}
	}
	size_t ngrps = json_object_array_length(__pwdgrpd_grall);
	if (__pwdgrpd_grall_off >= ngrps)
		return NSS_STATUS_NOTFOUND;
	struct json_object *j_grp;
	if (!json_object_array_get_idx(__pwdgrpd_grall, __pwdgrpd_grall_off)) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}
	return __pwdgrpd_parse_gr_json(j_grp, result, buffer, buflen, errnop);
}

enum nss_status _nss_pwdgrpd_setgrent()
{
	int http_status;
	char url[1024];

	snprintf(url, 1024, PWDGRPD_API_ENDPOINT"/getgrall?t=json");
	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		curl_global_cleanup();
		return NSS_STATUS_UNAVAIL;
	}

	struct binary_string http_res = {.payload = malloc(1), .size = 0};
	http_res.payload[0] = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_res);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 403) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status != 200) {
		free(http_res.payload);
		return NSS_STATUS_UNAVAIL;
	}

	__pwdgrpd_grall = json_tokener_parse(http_res.payload);
	free(http_res.payload);

	if (!__pwdgrpd_grall) {
		__pwdgrpd_grall_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	if (json_object_get_type(__pwdgrpd_grall) != json_type_array) {
		json_object_put(__pwdgrpd_grall);
		__pwdgrpd_grall = NULL;
		__pwdgrpd_grall_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	__pwdgrpd_grall_off = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_endgrent()
{
	if (__pwdgrpd_grall) json_object_put(__pwdgrpd_grall);
	__pwdgrpd_grall = NULL;
	__pwdgrpd_grall_off = -1;
	return NSS_STATUS_SUCCESS;
}

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t real_size = size * nmemb;
	struct binary_string *bs = (struct binary_string *) userp;

	char *ptr = realloc(bs->payload, bs->size + real_size + 1);
	if (!ptr) return 0;

	bs->payload = ptr;
	memcpy(&(bs->payload[bs->size]), contents, real_size);
	bs->size += real_size;
	bs->payload[bs->size] = 0; // always null terminated
	return real_size;
}

static inline char *safe_bufcpy(const char *src, char **ptr, const char *start, const size_t maxlen)
{
	size_t len = strlen(src);
	// we cannot copy, overflow!
	if (*ptr + len + 1 - start > maxlen) return NULL;
	// we do copy, append null terminate and return.
	char *oldptr = *ptr;
	memcpy(*ptr, src, len);
	(*ptr)[len] = '\x00';
	*ptr += len + 1;
	return oldptr;
}

static inline enum nss_status __pwdgrpd_pw(
	const char *url,
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	int http_status = -1;
	enum nss_status ret;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		curl_global_cleanup();
		*errnop = ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}

	struct binary_string http_res = {.payload = malloc(1), .size = 0};
	http_res.payload[0] = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_res);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		free(http_res.payload);
		*errnop = EIO;
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 404) {
		free(http_res.payload);
		return NSS_STATUS_NOTFOUND;
	}

	if (http_status != 200) {
		free(http_res.payload);
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	struct json_object *json = json_tokener_parse(http_res.payload);
	free(http_res.payload);
	if (!json) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}
	ret = __pwdgrpd_parse_pw_json(json, result, buffer, buflen, errnop);
	json_object_put(json);
	return NSS_STATUS_SUCCESS;
}

static inline enum nss_status __pwdgrpd_gr(
	const char *url,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	int http_status = -1;
	enum nss_status ret;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL *curl = curl_easy_init();
	if (!curl) {
		curl_global_cleanup();
		*errnop = ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}

	struct binary_string http_res = {.payload = malloc(1), .size = 0};
	http_res.payload[0] = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_res);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		free(http_res.payload);
		*errnop = EIO;
		return NSS_STATUS_UNAVAIL;
	}

	if (http_status == 404) {
		free(http_res.payload);
		return NSS_STATUS_NOTFOUND;
	}

	if (http_status != 200) {
		free(http_res.payload);
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	struct json_object *json = json_tokener_parse(http_res.payload);
	free(http_res.payload);
	if (!json) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}
	ret = __pwdgrpd_parse_gr_json(json, result, buffer, buflen, errnop);
	json_object_put(json);
	return ret;
}

static inline enum nss_status __pwdgrpd_parse_pw_json(
	const struct json_object *json,
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	struct json_object *j_name, *j_passwd, *j_uid, *j_gid, *j_gecos, *j_dir, *j_shell;

	if (
		!json_object_object_get_ex(json, "pw_name", &j_name) ||
		!json_object_object_get_ex(json, "pw_passwd", &j_passwd) ||
		!json_object_object_get_ex(json, "pw_uid", &j_uid) ||
		!json_object_object_get_ex(json, "pw_gid", &j_gid) ||
		!json_object_object_get_ex(json, "pw_gecos", &j_gecos) ||
		!json_object_object_get_ex(json, "pw_dir", &j_dir) ||
		!json_object_object_get_ex(json, "pw_shell", &j_shell)
	) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	char *ptr = buffer;

	result->pw_name   = safe_bufcpy(json_object_get_string(j_name)  , &ptr, buffer, buflen);
	result->pw_passwd = safe_bufcpy(json_object_get_string(j_passwd), &ptr, buffer, buflen);
	result->pw_gecos  = safe_bufcpy(json_object_get_string(j_gecos) , &ptr, buffer, buflen);
	result->pw_dir    = safe_bufcpy(json_object_get_string(j_dir)   , &ptr, buffer, buflen);
	result->pw_shell  = safe_bufcpy(json_object_get_string(j_shell) , &ptr, buffer, buflen);
	result->pw_uid    = (uid_t) json_object_get_int(j_uid);
	result->pw_gid    = (gid_t) json_object_get_int(j_gid);

	if (!result->pw_name || !result->pw_passwd || !result->pw_gecos || !result->pw_dir || !result->pw_shell) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}

static inline enum nss_status __pwdgrpd_parse_gr_json(
	const struct json_object *json,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	struct json_object *j_name, *j_passwd, *j_gid, *j_mem;

	if (
		!json_object_object_get_ex(json, "gr_name"  , &j_name) ||
		!json_object_object_get_ex(json, "gr_passwd", &j_passwd) ||
		!json_object_object_get_ex(json, "gr_gid"   , &j_gid) ||
		!json_object_object_get_ex(json, "gr_mem"   , &j_mem) ||
		json_object_get_type(j_mem) != json_type_array
	) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	char *ptr = buffer;

	result->gr_gid    = (gid_t) json_object_get_int(j_gid);
	result->gr_name   = safe_bufcpy(json_object_get_string(j_name)  , &ptr, buffer, buflen);
	result->gr_passwd = safe_bufcpy(json_object_get_string(j_passwd), &ptr, buffer, buflen);

	size_t nmems = json_object_array_length(j_mem);
	char **mem = (char **) ptr;
	char *ptr_mem_childs = ptr + (nmems + 1) * sizeof(char *);
	if (ptr_mem_childs - buffer > buflen) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	mem[nmems] = NULL; // member list should be null terminated char **

	for (int i = 0; i < nmems; i++) {
		json_object *m = json_object_array_get_idx(j_mem, i);
		mem[i] = safe_bufcpy(json_object_get_string(m), &ptr_mem_childs, buffer, buflen);
		if (mem[i] == NULL) {
			*errnop = ERANGE;
			return NSS_STATUS_TRYAGAIN;
		}
	}

	result->gr_mem = mem;

	if (!result->gr_name || !result->gr_passwd || !result->gr_mem) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}