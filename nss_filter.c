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

#include "version.h"

static char version[] = "nss_uc3 version " VERSION;

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

#ifdef DEBUG
void
printd(char *fmt, ...)
{
	va_list vp;
	static int debugging = -1;

	if (debugging == -1)
		debugging = getenv("NSSDEBUG") ? 1 : 0;

	if (debugging == 0)
		return;

	va_start(vp, fmt);
	vfprintf(stdout, fmt, vp);
	va_end(vp);
}
#else
# define printd(...)
#endif

void
subst(char **inp, char *find, char *replace, bool canfree, void (*filter)(char *p, int len))
{
	char *in;
	char *p;
	char *buf;
	char *start;

	if (inp == NULL)
		return;

	in = *inp;
	if (in == NULL)
		return;

	p = strstr(in, find);
	if (p == NULL)
		return;
	printd("in=%p, p=%p\n", in, p);

	buf = malloc(strlen(in) + strlen(replace) - strlen(find) + 1);
	strncpy(buf, in, (p-in));
	start = &buf[(p-in)];
	printd("buf=%p, start=%p\n", buf, start);
	strcpy(start, replace);

	if (filter)
		filter(start, strlen(replace));

	strcpy(start + strlen(replace), p + strlen(find));

	if (canfree)
		free(in);
	*inp = buf;
	return;
}


void
pass_capitalize(char *p, int len)
{
	if (p && len)
		p[0] = toupper(p[0]);
}


void
pass_lowercase(char *p, int len)
{
	if (p == NULL || len == 0)
		return;
	for (--len; len >= 0; len--)
		p[len] = tolower(p[len]);
}


void
pass_uppercase(char *p, int len)
{
	if (p == NULL || len == 0)
		return;
	for (--len; len >= 0; len--)
		p[len] = toupper(p[len]);
}


void
filter_passwd(struct passwd *pwd, char *buffer, size_t buflen)
{
	/* Ideally we want to add some means of configuring the
	 * filters that we apply here.  For now we'll simply
	 * hard-code a couple of examples. */

	/* N.B. there's no means of returning to your caller how much
	 * of buffer you have used up.  Thus when stacking NSS modules,
	 * you can't rely on buffer's being available for storing your
	 * updated data -- you don't know whether anyone has had at it
	 * already.
	 *
	 * It is /not/ safe to free members that you are replacing, unless
	 * you are certain that they lie outside of buffer[0:buflen].
	 * Is it safe simply to malloc more memory?  We'll try it.
	 */
	printd("pwd = %p, pwd->pw_gecos = %p, buffer = %p[%d]\n", pwd, pwd->pw_gecos, buffer, buflen);

#define CANFREE(p) (((p) < buffer) || ((p) > (buffer + buflen)))

	if (pwd->pw_gecos && strchr(pwd->pw_gecos, '&'))
		subst(&pwd->pw_gecos, "&", pwd->pw_name, CANFREE(pwd->pw_gecos),
		      pass_capitalize);
	if (pwd->pw_dir && strchr(pwd->pw_dir, '&'))
		subst(&pwd->pw_dir, "&", pwd->pw_name, CANFREE(pwd->pw_dir),
		      pass_lowercase);
	if (pwd->pw_shell && strchr(pwd->pw_shell, '&'))
		subst(&pwd->pw_shell, "&", pwd->pw_name, CANFREE(pwd->pw_shell),
		      pass_lowercase);
	return;
}


static void
init_wrapper (void)
{ 
  /* this is just to ensure that version is referenced, and not optimized away */
  version[0] = version[0];

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
