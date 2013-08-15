#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h> /* sysconf() */
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h> /* bool type */

#include "debug.h"
#include "util.h"

static void *nssinfo;

/* This function is part of nss itself.  It's available at runtime
 * but no user-land header declares it (currently?). */
extern enum nss_status (*__nss_lookup_function(void *nssinfo, char *func))();

static enum nss_status (*backend_getpwnam_r) (const char *name,
                        struct passwd *pwd,
                        char *buffer, size_t buflen, int *errnop);
static enum nss_status (*backend_getpwuid_r) (uid_t uid,
                        struct passwd *pwd,
                        char *buffer, size_t buflen, int *errnop);
static enum nss_status (*backend_setpwent_r) (int stayopen);
static enum nss_status (*backend_endpwent_r) (void);
static enum nss_status (*backend_getpwent_r) (
                        struct passwd *pwd,
                        char *buffer, size_t buflen, int *errnop);


static void
init_wrapper (void)
{ 
  if (__nss_database_lookup ("filter.backend.passwd", NULL, "files", &nssinfo) >= 0)
    { 
      backend_getpwnam_r = (void *) __nss_lookup_function (nssinfo, "getpwnam_r");
      backend_getpwuid_r = (void *) __nss_lookup_function (nssinfo, "getpwuid_r");
      backend_setpwent_r = (void *) __nss_lookup_function (nssinfo, "setpwent_r");
      backend_endpwent_r = (void *) __nss_lookup_function (nssinfo, "endpwent_r");
      backend_getpwent_r = (void *) __nss_lookup_function (nssinfo, "getpwent_r");
    }
}


enum nss_status
_nss_filter_getpwnam_r(const char *name, struct passwd *pwd,
                       char *buf, size_t buflen, int *errnop)
{
	enum nss_status r;

	printd("nss_filter_getpwuid_r\n");

	if (nssinfo == NULL)
		init_wrapper();

	if (backend_getpwnam_r == NULL)
		return NSS_STATUS_NOTFOUND;

	/* Call into filter backend */
	r = backend_getpwnam_r(name, pwd, buf, buflen, errnop);
	if (r != NSS_STATUS_SUCCESS)
		return r;

	/* Perform filtering and return */
	filter_passwd(pwd, buf, buflen);
	return r;
}


enum nss_status
_nss_filter_getpwuid_r(uid_t uid, struct passwd *pwd,
                       char *buf, size_t buflen, int *errnop)
{
	enum nss_status r;

	printd("nss_filter_getpwuid_r\n");

	if (nssinfo == NULL)
		init_wrapper();

	if (backend_getpwuid_r == NULL)
		return NSS_STATUS_NOTFOUND;

	/* Call into filter backend */
	r = backend_getpwuid_r(uid, pwd, buf, buflen, errnop);
	if (r != NSS_STATUS_SUCCESS)
		return r;

	/* Perform filtering and return */
	filter_passwd(pwd, buf, buflen);
	return r;
}


enum nss_status
_nss_filter_getpwent_r(struct passwd *pwd,
                       char *buf, size_t buflen, int *errnop)
{
	enum nss_status r;

	printd("nss_filter_getpwent_r\n");

	if (nssinfo == NULL)
		init_wrapper();

	if (backend_getpwent_r == NULL)
		return NSS_STATUS_NOTFOUND;

	/* Call into filter backend */
	r = backend_getpwent_r(pwd, buf, buflen, errnop);
	if (r != NSS_STATUS_SUCCESS)
		return r;

	/* Perform filtering and return */
	filter_passwd(pwd, buf, buflen);
	return r;
}


enum nss_status
_nss_filter_setpwent_r(int stayopen)
{
	enum nss_status r = NSS_STATUS_UNAVAIL;

	printd("nss_filter_setpwent_r\n");

	if (nssinfo == NULL)
		init_wrapper();

	if (backend_setpwent_r)
		r = backend_setpwent_r(stayopen);

	return r;
}


enum nss_status
_nss_filter_endpwent_r(void)
{
	enum nss_status r = NSS_STATUS_SUCCESS;

	printd("nss_filter_endpwent_r\n");

	if (nssinfo == NULL)
		init_wrapper();

	if (backend_endpwent_r)
		backend_endpwent_r();

	return r;
}
