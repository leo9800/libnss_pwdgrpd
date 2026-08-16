#include <json-c/json.h>
#include <curl/curl.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>
#include <ini.h>
#include "nss-pwdgrpd.h"

#ifndef LIBNSS_PWDGRPD_CONFIG_PATH
#define LIBNSS_PWDGRPD_CONFIG_PATH "/etc/libnss-pwdgrpd.ini"
#endif

#ifndef LIBNSS_PWDGRPD_MAX_URL_LEN
#define LIBNSS_PWDGRPD_MAX_URL_LEN 1024
#endif

#ifndef LIBNSS_PWDGRPD_HTTPS_ONLY
#define LIBNSS_PWDGRPD_HTTPS_ONLY true
#endif

struct pwdgrpd_config {
	bool ok;
	const char endpoint[LIBNSS_PWDGRPD_MAX_URL_LEN];
	const char proxy[LIBNSS_PWDGRPD_MAX_URL_LEN];
	bool ignore_proxy;
	time_t timeout;
};

struct pwdgrpd_ents {
	struct json_object *pwds;
	struct json_object *grps;
	off_t pwd_off;
	off_t grp_off;
};

static struct pwdgrpd_config __pwdgrpd_config = {.ok = false, .endpoint = "\x00", .proxy = "\x00", .ignore_proxy = false, .timeout = 10};
static struct pwdgrpd_ents __pwdgrpd_ents = {.pwds = NULL, .grps = NULL, .pwd_off = -1, .grp_off = -1};

static int __pwdgrpd_parse_config(void *, const char *, const char *, const char *);
static size_t __pwdgrpd_curl_write_cb(void *, size_t, size_t, void *);
static inline enum nss_status __pwdgrpd_curl(const char *, struct json_object **, int *);
static inline char *__pwdgrpd_safe_bufcpy(const char *, char **, const char *, const size_t);
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
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	enum nss_status ret;
	struct json_object *json;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	snprintf_ret = snprintf(url, sizeof(url), "%s/getpwnam/%s?t=json", __pwdgrpd_config.endpoint, name);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) {*errnop = E2BIG; ret = NSS_STATUS_UNAVAIL; goto end;}
	ret = __pwdgrpd_curl(url, &json, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	ret = __pwdgrpd_parse_pw_json(json, result, buffer, buflen, errnop);
end:
	if (json) {json_object_put(json); json = NULL;}
	return ret;
}

enum nss_status _nss_pwdgrpd_getpwuid_r(
	const uid_t uid,
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	enum nss_status ret;
	struct json_object *json;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	snprintf_ret = snprintf(url, sizeof(url), "%s/getpwuid/%d?t=json", __pwdgrpd_config.endpoint, uid);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) {*errnop = E2BIG; ret = NSS_STATUS_UNAVAIL; goto end;}
	ret = __pwdgrpd_curl(url, &json, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	ret = __pwdgrpd_parse_pw_json(json, result, buffer, buflen, errnop);
end:
	if (json) {json_object_put(json); json = NULL;}
	return ret;
}

enum nss_status _nss_pwdgrpd_getgrnam_r(
	const char *name,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	enum nss_status ret;
	struct json_object *json;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	snprintf_ret = snprintf(url, sizeof(url), "%s/getgrnam/%s?t=json", __pwdgrpd_config.endpoint, name);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) {*errnop = E2BIG; ret = NSS_STATUS_UNAVAIL; goto end;}
	ret = __pwdgrpd_curl(url, &json, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	ret = __pwdgrpd_parse_gr_json(json, result, buffer, buflen, errnop);
end:
	if (json) {json_object_put(json); json = NULL;}
	return ret;
}

enum nss_status _nss_pwdgrpd_getgrgid_r(
	const gid_t gid,
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	enum nss_status ret;
	struct json_object *json;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	snprintf_ret = snprintf(url, sizeof(url), "%s/getgrgid/%d?t=json", __pwdgrpd_config.endpoint, gid);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) {*errnop = E2BIG; ret = NSS_STATUS_UNAVAIL; goto end;}
	ret = __pwdgrpd_curl(url, &json, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	ret = __pwdgrpd_parse_gr_json(json, result, buffer, buflen, errnop);
end:
	if (json) {json_object_put(json); json = NULL;}
	return ret;
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
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	struct json_object *json;
	enum nss_status ret;
	size_t ngids;
	size_t newsize;
	gid_t *new_groupsp;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	snprintf_ret = snprintf(url, LIBNSS_PWDGRPD_MAX_URL_LEN, "%s/initgroups/%s?t=json&b=gid", __pwdgrpd_config.endpoint, user);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) {*errnop = E2BIG; ret = NSS_STATUS_UNAVAIL; goto end;};
	ret = __pwdgrpd_curl(url, &json, errnop);
	if (ret != NSS_STATUS_SUCCESS) {goto end;}
	// returns must be an array of additional gids
	if (json_object_get_type(json) != json_type_array) {*errnop = EINVAL; ret = NSS_STATUS_UNAVAIL; goto end;}
	ngids = json_object_array_length(json);
	// check if we need expand the groupsp array
	if (*size - *start <= ngids + 1) { // 1 gid specified in param + other retrieved by API
		// double the size if it is not exceeding the limit
		newsize = limit > (*size * 2) ? (*size * 2) : limit;
		new_groupsp = realloc(*groupsp, newsize);
		// error out if we could not expand it due to OOM
		if (new_groupsp == NULL) {*errnop = ENOMEM; ret = NSS_STATUS_TRYAGAIN; goto end;}
		// copy pointer if expand succeeded
		*groupsp = new_groupsp;
	}

	// add primary group of user (i.e. gid specified in passwd file)
	(*groupsp)[*start] = group;
	*start += 1;

	// copy every single additional gid to groupsp
	for (int i = 0; i < ngids; i++) {
		(*groupsp)[*start] = (gid_t) json_object_get_int(json_object_array_get_idx(json, i));
		*start += 1;
	}

	ret = NSS_STATUS_SUCCESS;
end:
	if (json) {json_object_put(json); json = NULL;};
	return ret;
}

enum nss_status _nss_pwdgrpd_getpwent_r(
	struct passwd *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	enum nss_status ret;
	size_t npwds;
	struct json_object *j_pwd;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	// if not initialized ...
	// this could happen because glibc allows user to call get[pw,gr]ent() without calling set[pw,gr]ent() in advance
	if (__pwdgrpd_ents.pwd_off == -1) {
		// we try initialize it ...
		_nss_pwdgrpd_setpwent();
		// if it won't initialize again, then we assume doing so is not supported
		// as the server rejects enumeration
		if (__pwdgrpd_ents.pwd_off == -1) {ret = NSS_STATUS_UNAVAIL; goto end;}
	}
	npwds = json_object_array_length(__pwdgrpd_ents.pwds);
	// if we reached the last child ...
	if (__pwdgrpd_ents.pwd_off >= npwds) {ret = NSS_STATUS_NOTFOUND; goto end;}

	j_pwd = json_object_array_get_idx(__pwdgrpd_ents.pwds, __pwdgrpd_ents.pwd_off);

	// if we could not get child ...
	// this is unlikely to happen unless something goes really wrong that desync pwds and pwd_off
	if (!j_pwd) {*errnop = EINVAL; ret = NSS_STATUS_UNAVAIL; goto end;}

	ret = __pwdgrpd_parse_pw_json(j_pwd, result, buffer, buflen, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	__pwdgrpd_ents.pwd_off += 1;
end:
	return ret;
}

enum nss_status _nss_pwdgrpd_setpwent()
{
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	int errnop;

	if (!__pwdgrpd_config.ok) return NSS_STATUS_UNAVAIL;

	snprintf_ret = snprintf(url, LIBNSS_PWDGRPD_MAX_URL_LEN, "%s/getpwall?t=json", __pwdgrpd_config.endpoint);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) return NSS_STATUS_UNAVAIL;

	__pwdgrpd_curl(url, &__pwdgrpd_ents.pwds, &errnop);

	if (!__pwdgrpd_ents.pwds) {
		__pwdgrpd_ents.pwd_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	if (json_object_get_type(__pwdgrpd_ents.pwds) != json_type_array) {
		json_object_put(__pwdgrpd_ents.pwds);
		__pwdgrpd_ents.pwds = NULL;
		__pwdgrpd_ents.pwd_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	__pwdgrpd_ents.pwd_off = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_endpwent()
{
	if (!__pwdgrpd_config.ok) return NSS_STATUS_UNAVAIL;
	if (__pwdgrpd_ents.pwds) json_object_put(__pwdgrpd_ents.pwds);
	__pwdgrpd_ents.pwds = NULL;
	__pwdgrpd_ents.pwd_off = -1;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_getgrent_r(
	struct group *result,
	char *buffer,
	size_t buflen,
	int *errnop
)
{
	enum nss_status ret;
	size_t ngrps;
	struct json_object *j_grp;

	if (!__pwdgrpd_config.ok) {*errnop = EFAULT; ret = NSS_STATUS_UNAVAIL; goto end;}
	// if not initialized ...
	// this could happen because glibc allows user to call get[pw,gr]ent() without calling set[pw,gr]ent() in advance
	if (__pwdgrpd_ents.grp_off == -1) {
		// we try initialize it ...
		_nss_pwdgrpd_setgrent();
		// if it won't initialize again, then we assume doing so is not supported
		// as the server rejects enumeration
		if (__pwdgrpd_ents.grp_off == -1) {ret = NSS_STATUS_UNAVAIL; goto end;}
	}
	ngrps = json_object_array_length(__pwdgrpd_ents.grps);
	// if we reached the last child ...
	if (__pwdgrpd_ents.grp_off >= ngrps) {ret = NSS_STATUS_NOTFOUND; goto end;}

	j_grp = json_object_array_get_idx(__pwdgrpd_ents.grps, __pwdgrpd_ents.grp_off);

	// if we could not get child ...
	// this is unlikely to happen unless something goes really wrong that desync pwds and pwd_off
	if (!j_grp) {*errnop = EINVAL; ret = NSS_STATUS_UNAVAIL; goto end;}

	ret = __pwdgrpd_parse_gr_json(j_grp, result, buffer, buflen, errnop);
	if (ret != NSS_STATUS_SUCCESS) goto end;
	__pwdgrpd_ents.grp_off += 1;
end:
	return ret;
}

enum nss_status _nss_pwdgrpd_setgrent()
{
	char url[LIBNSS_PWDGRPD_MAX_URL_LEN];
	int snprintf_ret;
	int errnop;

	if (!__pwdgrpd_config.ok) return NSS_STATUS_UNAVAIL;

	snprintf_ret = snprintf(url, LIBNSS_PWDGRPD_MAX_URL_LEN, "%s/getgrall?t=json", __pwdgrpd_config.endpoint);
	if (snprintf_ret < 0 || snprintf_ret > LIBNSS_PWDGRPD_MAX_URL_LEN) return NSS_STATUS_UNAVAIL;

	__pwdgrpd_curl(url, &__pwdgrpd_ents.grps, &errnop);

	if (!__pwdgrpd_ents.grps) {
		__pwdgrpd_ents.grp_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	if (json_object_get_type(__pwdgrpd_ents.grps) != json_type_array) {
		json_object_put(__pwdgrpd_ents.grps);
		__pwdgrpd_ents.grps = NULL;
		__pwdgrpd_ents.grp_off = -1;
		return NSS_STATUS_TRYAGAIN;
	}

	__pwdgrpd_ents.grp_off = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_pwdgrpd_endgrent()
{
	if (!__pwdgrpd_config.ok) return NSS_STATUS_UNAVAIL;
	if (__pwdgrpd_ents.grps) json_object_put(__pwdgrpd_ents.grps);
	__pwdgrpd_ents.grps = NULL;
	__pwdgrpd_ents.grp_off = -1;
	return NSS_STATUS_SUCCESS;
}

static inline enum nss_status __pwdgrpd_curl(
	const char *url,
	struct json_object **json,
	int *errnop
)
{
	enum nss_status ret;
	CURL *curl;
	int http_status;
	struct binary_string http_response;

	http_response.size = 0;
	http_response.payload = malloc(1);
	http_response.payload[0] = '\x00';

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (!curl) {*errnop = ENOMEM; ret = NSS_STATUS_TRYAGAIN; goto end;}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &__pwdgrpd_curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &http_response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, __pwdgrpd_config.timeout);

	if (__pwdgrpd_config.ignore_proxy)
		curl_easy_setopt(curl, CURLOPT_PROXY, "");
	else if (strlen(__pwdgrpd_config.proxy) > 0)
		curl_easy_setopt(curl, CURLOPT_PROXY, __pwdgrpd_config.proxy);

	// if curl request failed (e.g. timeout) ...
	if (curl_easy_perform(curl) != CURLE_OK) {*errnop = EIO; ret = NSS_STATUS_TRYAGAIN; goto end;}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

	// if getpwall/getgrall and server disables enumeration ...
	if (http_status == 403) {ret = NSS_STATUS_UNAVAIL; goto end;}
	// if get[pw,gr][uid,gid,nam] could not find such user/group ...
	if (http_status == 404) {ret = NSS_STATUS_NOTFOUND; goto end;}
	// other status code than 200
	// not likely to happen unless server not properly implemented
	if (http_status != 200) {*errnop = EINVAL; ret = NSS_STATUS_UNAVAIL; goto end;}

	*json = json_tokener_parse(http_response.payload);

	// if server did not return a valid json ...
	// not likely to happend unless server not properly implemented (again)
	if (!*json) {*errnop = EINVAL; ret = NSS_STATUS_UNAVAIL; goto end;}

	// succeed ...
	ret = NSS_STATUS_SUCCESS;
end:
	if (http_response.payload) {free(http_response.payload); http_response.payload = NULL;}
	if (curl) {curl_easy_cleanup(curl); curl = NULL;}
	curl_global_cleanup();
	return ret;
}

static int __pwdgrpd_parse_config(
	void *userp,
	const char *section,
	const char *name,
	const char *value
)
{
	struct pwdgrpd_config *config = (struct pwdgrpd_config *) userp;

	if (strcmp(section, "pwdgrpd") == 0 && strcmp(name, "endpoint") == 0) {
		strcpy((char *) config->endpoint, value);
		return 1;
	}

	if (strcmp(section, "pwdgrpd") == 0 && strcmp(name, "proxy") == 0) {
		strcpy((char *) config->proxy, value);
		return 1;
	}

	if (strcmp(section, "pwdgrpd") == 0 && strcmp(name, "ignore_proxy") == 0) {
		if (strcmp("true", value) == 0) config->ignore_proxy = true;
		if (strcmp("false", value) == 0) config->ignore_proxy = false;
		return 1;
	}

	if (strcmp(section, "pwdgrpd") == 0 && strcmp(name, "timeout") == 0) {
		config->timeout = (time_t) atol(value);
		return 1;
	}

	return 0;
}

static size_t __pwdgrpd_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
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

static inline char *__pwdgrpd_safe_bufcpy(const char *src, char **ptr, const char *start, const size_t maxlen)
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
		!json_object_object_get_ex(json, "pw_name"  , &j_name) ||
		!json_object_object_get_ex(json, "pw_passwd", &j_passwd) ||
		!json_object_object_get_ex(json, "pw_uid"   , &j_uid) ||
		!json_object_object_get_ex(json, "pw_gid"   , &j_gid) ||
		!json_object_object_get_ex(json, "pw_gecos" , &j_gecos) ||
		!json_object_object_get_ex(json, "pw_dir"   , &j_dir) ||
		!json_object_object_get_ex(json, "pw_shell" , &j_shell)
	) {
		*errnop = EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	char *ptr = buffer;

	result->pw_name   = __pwdgrpd_safe_bufcpy(json_object_get_string(j_name)  , &ptr, buffer, buflen);
	result->pw_passwd = __pwdgrpd_safe_bufcpy(json_object_get_string(j_passwd), &ptr, buffer, buflen);
	result->pw_gecos  = __pwdgrpd_safe_bufcpy(json_object_get_string(j_gecos) , &ptr, buffer, buflen);
	result->pw_dir    = __pwdgrpd_safe_bufcpy(json_object_get_string(j_dir)   , &ptr, buffer, buflen);
	result->pw_shell  = __pwdgrpd_safe_bufcpy(json_object_get_string(j_shell) , &ptr, buffer, buflen);
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
	result->gr_name   = __pwdgrpd_safe_bufcpy(json_object_get_string(j_name)  , &ptr, buffer, buflen);
	result->gr_passwd = __pwdgrpd_safe_bufcpy(json_object_get_string(j_passwd), &ptr, buffer, buflen);

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
		mem[i] = __pwdgrpd_safe_bufcpy(json_object_get_string(m), &ptr_mem_childs, buffer, buflen);
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

__attribute__((constructor)) 
void __pwdgrpd_init(void) {
	CURLU *curlu;
	CURLUcode curlu_code;

	ini_parse(LIBNSS_PWDGRPD_CONFIG_PATH, &__pwdgrpd_parse_config, (void *) &__pwdgrpd_config);
	if (__pwdgrpd_config.timeout < 0) goto fail;
#if LIBNSS_PWDGRPD_HTTPS_ONLY == true
	if (strncmp(__pwdgrpd_config.endpoint, "https://", 8)) goto fail;
#else
	if (strncmp(__pwdgrpd_config.endpoint, "https://", 8) && \
		strncmp(__pwdgrpd_config.endpoint, "http://", 7)) goto fail;
#endif
	curlu = curl_url();
	if (!curlu) goto fail;
	curlu_code = curl_url_set(curlu, CURLUPART_URL, __pwdgrpd_config.endpoint, CURLU_DISALLOW_USER | CURLU_GUESS_SCHEME);
	curl_url_cleanup(curlu);
	if (curlu_code != CURLUE_OK) goto fail;
	__pwdgrpd_config.ok = true;
	return;
fail:
	__pwdgrpd_config.ok = false;
}
