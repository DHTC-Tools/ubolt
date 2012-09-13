#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

enum nss_status
group(const char *name, gid_t gid, struct group *grp,
      char *buf, size_t buflen, struct group **result)
{
	struct passwd *pw, *pwp;
	char *bufp;
	int len;
	int maxpwbuflen;
	char *pwdata = NULL;

#ifdef DEBUG
	printf("name=%s, gid=%d, buf=%p, buflen=%d\n", name, (int) gid, buf, buflen);
#endif

	/* Preset the result value so that we don't forget to do this
	 * when returning early with an error. */
	*result = NULL;

	/* We'll compute the required buffer length. If enough space is not
	 * given to us, we can return an error. */

	/* Init required length as size of group name */
	len = strlen(name) + 1;

	/* Add empty password string to requirements */
	len += 1;

	/* Search for a user with uid == gid */
	pw = getpwuid((uid_t) gid);
	if (pw == NULL) {
#ifdef DEBUG
		printf("no\n");
#endif
		/* Not found, add space for empty member list to requirements */
		len += sizeof(char *);
	}
	else {
#ifdef DEBUG
		printf("yes\n");
#endif
		/* If found, add space for 1-element member list to requirements */
		len += sizeof(char *) * 2;
		len += strlen(pw->pw_name) + 1;
	}

	/* If not enough space provided, return */
	if (buflen < len) {
		/* Free transient data */
		return NSS_STATUS_TRYAGAIN;
	}

	/* Point to provided buffer.  We will stack on internal strings. */
	bufp = buf;

	if (pw)
		name = pw->pw_name;

	/* Stack on group name */
	strcpy(bufp, name);
	grp->gr_name = bufp;
	bufp += strlen(name);

	/* Stack on empty password */
	*bufp = '\0';
	grp->gr_passwd = bufp;
	bufp++;

	/* Set gid */
	grp->gr_gid = gid;

	/* Stack on group member list */
	if (pw) {
		char *pwname, **gp;

		strcpy(pwname = bufp, pw->pw_name);
		bufp += strlen(pw->pw_name) + 1;

		grp->gr_mem = gp = (char **)bufp;
		*gp++ = pwname;
		*gp++ = NULL;
	}
	else {
		char **gp;
		grp->gr_mem = gp = (char **)bufp;
		*gp++ = NULL;
	}

	*result = grp;
	return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_identity_getgrnam_r(const char *name, struct group *grp,
                         char *buf, size_t buflen, struct group **result)
{
	gid_t gid;
	char *p, *end;

#ifdef DEBUG
	printf("nss_identity_getgrgid_r\n");
	fflush(stdout);
#endif

	if (strncmp(name, "group", 5))
		return NSS_STATUS_NOTFOUND;

	/* Extract gid from requested name */
	p = (char *) &name[5];
	if (*p == '_')
		p++;
	gid = (gid_t) strtoul(p, &end, 10);

	/* Hand off to generic group backend */
	return group(name, gid, grp, buf, buflen, result);
}


enum nss_status
_nss_identity_getgrgid_r(gid_t gid, struct group *grp,
                         char *buf, size_t buflen, struct group **result)
{
	char name[1024];

#ifdef DEBUG
	printf("nss_identity_getgrgid_r\n");
	fflush(stdout);
#endif

	snprintf(name, sizeof(name), "group_%d", (int) gid);

	/* Hand off to generic group backend */
	return group(name, gid, grp, buf, buflen, result);
}


