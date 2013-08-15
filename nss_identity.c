#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h> /* sysconf() */

#include "debug.h"

enum nss_status
group(const char *name, gid_t gid, struct group *grp,
      char *buf, size_t buflen, struct group **result)
{
	struct passwd *pw, *pwp;
	char *bufp;
	int len = 0;
	int maxpwbuflen;
	char *pwdata = NULL;
	char grname[1024];
	int r;

	printd("name=%s, gid=%d, buf=%p, buflen=%d\n", name, (int) gid, buf, buflen);

	/* Preset the result value so that we don't forget to do this
	 * when returning early with an error. */
	*result = NULL;

	/* We'll compute the required buffer length. If enough space is not
	 * given to us, we can return an error. */

	/* Prepare for getpw*_r calls */
	maxpwbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	pwdata = malloc(maxpwbuflen);
	pw = malloc(sizeof(struct passwd));

	if (name) {
		/* We are performing getgrnam */
		r = getpwnam_r(name, pw, pwdata, maxpwbuflen, &pwp);

		/* If no match, but group matches group_####, extract gid */
		if (r != 0 || pwp == NULL) {
			if (!strncmp(name, "group_", 6)) {
				char *p, *end;

				/* Extract gid from requested name */
				p = (char *) &name[6];
				gid = (gid_t) strtoul(p, &end, 10);

				/* Convert to gid request */
				r = getpwuid_r((uid_t) gid, pw, pwdata, maxpwbuflen, &pwp);
			}
		}
	}
	else {
		/* We are performing getgrgid - search for a user with uid == gid */
		r = getpwuid_r((uid_t) gid, pw, pwdata, maxpwbuflen, &pwp);
	}

	printd("r = %d, pwp = %p, name = %p, gid = %d\n", r, pwp, name, gid);

	if (r != 0 || pwp == NULL) {
		printd("no\n");
		/* Not found, add space for empty member list to requirements */
		len += sizeof(char *);
	}

	else {
		printd("yes\n");
		/* If found, add space for 1-element member list to requirements */
		len += sizeof(char *) * 2;
		len += strlen(pwp->pw_name) + 1;
	}

	if (pwp && name == NULL) {
		name = pwp->pw_name;
	}
	else if (name == NULL) {
		snprintf(grname, sizeof(grname), "group_%d", gid);
		name = grname;
	}
	else if (pwp && gid == -1) {
		gid = (gid_t) pwp->pw_uid;
	}
	else if (gid == -1) {
		/* Free transient data */
		if (pwp && pwp != pw)
			free(pwp);
		free(pw);
		free(pwdata);
		return NSS_STATUS_NOTFOUND;
	}

	/* Init required length with size of group name */
	len += strlen(name) + 1;

	/* Add empty password string to requirements */
	len += 1;

	/* If not enough space provided, return */
	if (buflen < len) {
		/* Free transient data */
		if (pwp && pwp != pw)
			free(pwp);
		free(pw);
		free(pwdata);
		return NSS_STATUS_TRYAGAIN;
	}

	/* Point to provided buffer.  We will stack on internal strings. */
	bufp = buf;

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
	if (pwp) {
		char *pwname, **gp;

		strcpy(pwname = bufp, pwp->pw_name);
		bufp += strlen(pwp->pw_name) + 1;

		grp->gr_mem = gp = (char **)bufp;
		*gp++ = pwname;
		*gp++ = NULL;
	}
	else {
		char **gp;
		grp->gr_mem = gp = (char **)bufp;
		*gp++ = NULL;
	}

	/* Free transient data */
	if (pwp && pwp != pw)
		free(pwp);
	free(pw);
	free(pwdata);

	*result = grp;
	return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_identity_getgrnam_r(const char *name, struct group *grp,
                         char *buf, size_t buflen, struct group **result)
{
	printd("nss_identity_getgrgid_r\n");

	/* Hand off to generic group backend */
	return group(name, -1, grp, buf, buflen, result);
}


enum nss_status
_nss_identity_getgrgid_r(gid_t gid, struct group *grp,
                         char *buf, size_t buflen, struct group **result)
{
	printd("nss_identity_getgrgid_r\n");

	/* Hand off to generic group backend */
	return group(NULL, gid, grp, buf, buflen, result);
}


