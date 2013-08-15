#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <syslog.h>

#include "util.h"

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


/* Map syslog names */
struct namemap {
	char *name;
	int value;
};

#define def(n) { #n, n }
struct namemap syslogs[] = {
	/* standard facilities */
	def(LOG_KERN),
	def(LOG_USER),
	def(LOG_MAIL),
	def(LOG_DAEMON),
	def(LOG_AUTH),
	def(LOG_SYSLOG),
	def(LOG_LPR),
	def(LOG_NEWS),
	def(LOG_UUCP),
	
	/* nonstandard facilities */
#ifdef LOG_MARK
	def(LOG_MARK),
#endif
#ifdef LOG_AUDIT
	def(LOG_AUDIT),
#endif
#ifdef LOG_CRON
	def(LOG_CRON),
#endif

	/* local facilities */
	def(LOG_LOCAL0),
	def(LOG_LOCAL1),
	def(LOG_LOCAL2),
	def(LOG_LOCAL3),
	def(LOG_LOCAL4),
	def(LOG_LOCAL5),
	def(LOG_LOCAL6),
	def(LOG_LOCAL7),

	/* priorities */
	def(LOG_EMERG),
	def(LOG_ALERT),
	def(LOG_CRIT),
	def(LOG_ERR),
	def(LOG_WARNING),
	def(LOG_NOTICE),
	def(LOG_INFO),
	def(LOG_DEBUG),
	{ NULL, 0 }
};
#undef def


int
get_syslog(char *name)
{
	int i;

	for (i = 0; syslogs[i].name; i++) {
		if (!strcasecmp(name, syslogs[i].name))
			return syslogs[i].value;
		if (!strncmp(syslogs[i].name, "LOG_", 4) &&
		    !strcasecmp(name, &syslogs[i].name[4]))
			return syslogs[i].value;
	}

	return -1;
}


/* Create and populate a context based on a given PAM handle and
 * module name. */
struct context *
get_context(pam_handle_t *pamh, char *name, char *module)
{
	struct context *ctx;

	syslog(LOG_AUTH|LOG_DEBUG, "get_context (%s) in", module ? module : "??");

	ctx = malloc(sizeof(struct context));
	memset(ctx, 0, sizeof(struct context));

	syslog(LOG_AUTH|LOG_DEBUG, "uname");
	uname(&ctx->uts);
	syslog(LOG_AUTH|LOG_DEBUG, "pam_get_user");
	pam_get_user(pamh, &ctx->user, NULL);
	syslog(LOG_AUTH|LOG_DEBUG, "pam_get_item(PAM_SERVICE)");
	pam_get_item(pamh, PAM_SERVICE, (PAM_CONST void **)&ctx->svc);
	syslog(LOG_AUTH|LOG_DEBUG, "pam_get_item(PAM_RHOST)");
	pam_get_item(pamh, PAM_RHOST, (PAM_CONST void **)&ctx->rhost);
	syslog(LOG_AUTH|LOG_DEBUG, "strdup");
	ctx->module = strdup(module);
	ctx->name = strdup(name);
	ctx->log = LOG_AUTH;

	if (ctx->user == NULL)
		ctx->user = "(unknown)";
	if (ctx->svc == NULL)
		ctx->svc = "(unknown)";
	if (ctx->rhost == NULL)
		ctx->rhost = "(local)";

	syslog(LOG_AUTH|LOG_DEBUG, "get_context (%s) out", module ? module : "??");
	return ctx;
}


/* Release a context structure cleanly. */
void
free_context(struct context *ctx)
{
	if (ctx->module)
		free((void *)ctx->module);
	if (ctx->name)
		free((void *)ctx->name);
	free(ctx);
}


/* General syslog front-end */
void
msg(struct context *ctx, int level, char *fmt, ...)
{
	char fmtbuf[1024];
	char msgbuf[1024];
	va_list vp;

	va_start(vp, fmt);
	snprintf(fmtbuf, sizeof(fmtbuf), "%s<%s>: %s",
	         ctx->name, ctx->module ? ctx->module : "unknown", fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, vp);
	va_end(vp);

	syslog(ctx->log|level, "%s", msgbuf);
}


/* Set up environment with pam params */
void
env_setup(pam_handle_t *pamh, char *type)
{
	char tmp[1024];
	char *p;

	pam_get_item(pamh, PAM_RHOST, (PAM_CONST void **)&p);
	if (p == NULL)
		p = "";
    snprintf(tmp, sizeof(tmp), "PAM_RHOST=%s", p);
	putenv(strdup(tmp));

	pam_get_item(pamh, PAM_RUSER, (PAM_CONST void **)&p);
	if (p == NULL)
		p = "";
    snprintf(tmp, sizeof(tmp), "PAM_RUSER=%s", p);
	putenv(strdup(tmp));

	pam_get_item(pamh, PAM_SERVICE, (PAM_CONST void **)&p);
	if (p == NULL)
		p = "";
    snprintf(tmp, sizeof(tmp), "PAM_SERVICE=%s", p);
	putenv(strdup(tmp));

	pam_get_item(pamh, PAM_TTY, (PAM_CONST void **)&p);
	if (p == NULL)
		p = "";
    snprintf(tmp, sizeof(tmp), "PAM_TTY=%s", p);
	putenv(strdup(tmp));

	pam_get_user(pamh, (PAM_CONST char **)&p, NULL);
	if (p == NULL)
		p = "";
    snprintf(tmp, sizeof(tmp), "PAM_USER=%s", p);
	putenv(strdup(tmp));

	if (type == NULL)
		type = "unknown";
    snprintf(tmp, sizeof(tmp), "PAM_TYPE=%s", type);
	putenv(strdup(tmp));
}


/* Execute a program (identified in argv[]) under the given context.
 * Collect output and log it. */
int
sh(struct context *ctx, char **argv)
{
	char msgbuf[1024];
	int off = 0;
	int i;
	pid_t pid;
	int stat;
	int sock[2];
	int null;
	void *oldhandler = NULL;

	memset(msgbuf, 0, sizeof(msgbuf));

	/* Log exec */
	for (i = 0; argv[i]; i++) {
		msgbuf[off++] = '"';
		strncpy(&msgbuf[off], argv[i], sizeof(msgbuf) - off - 1);
		off += strlen(&msgbuf[off]);
		msgbuf[off++] = '"';
		msgbuf[off++] = ' ';
	}
	msg(ctx, LOG_INFO, "executing %s", msgbuf);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock) != 0) {
		msg(ctx, LOG_WARNING, "cannnot socketpair: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	/* restore default sigchld handler, saving the prior handler.
	 * (sigchld handler might have been set by the pam agent.) */
	oldhandler = signal(SIGCHLD, SIG_DFL);

	pid = fork();
	if (pid < 0) {
		/* error - restore original sigchld handler and return */
		signal(SIGCHLD, oldhandler);
		msg(ctx, LOG_WARNING, "cannnot fork: %s", strerror(errno));
		close(sock[0]);
		close(sock[1]);
		return PAM_SYSTEM_ERR;
	}

	else if (pid == 0) {
		/* child - keep sig_dfl sigchld handler until death do it part */
		close(sock[0]);
		null = open("/dev/null", O_RDONLY);
		dup2(null, 0);
		dup2(sock[1], 1);
		dup2(sock[1], 2);
		execv(argv[0], argv);
		fprintf(stderr, "cannot exec: %s\n", strerror(errno));
		fflush(stderr);
		exit(255);
	}

	else {
		/* parent - restore sigchld handler -only- after reaping child */
		FILE *fp;
		char buf[1024];
		char *p;

		close(sock[1]);
		fp = fdopen(sock[0], "r");
		while (fgets(buf, sizeof(buf)-1, fp) != NULL) {
			buf[sizeof(buf)-1] = '\0';
			p = strchr(buf, '\n');
			if (p)
				*p = '\0';
			p = strchr(buf, '\r');
			if (p)
				*p = '\0';
			msg(ctx, LOG_INFO, "exec: %s", buf);
		}
		fclose(fp);
		close(sock[0]);

		waitpid(pid, &stat, 0);
		signal(SIGCHLD, oldhandler);
		if (WEXITSTATUS(stat) != 0) {
			msg(ctx, LOG_INFO, "exec returned %d", WEXITSTATUS(stat));
			return PAM_SYSTEM_ERR;
		}
	}

	return PAM_SUCCESS;
}


#define S(s) (s ? s : "")


/* Copy the given string, expanding % tokens under context. */
char *
expand(struct context *ctx, char *fmt)
{
	char buf[1024];
	char *sp, *dp;

	memset(buf, 0, sizeof(buf));

	sp = fmt;
	dp = buf;
	while (sp && *sp && (dp - buf) < sizeof(buf) - 1) {
		if (*sp == '%') {
			sp++;
			switch (*sp) {
				/* %% */
				case '%':
					*dp++ = *sp++;
					break;

				/* %u: user name */
				case 'u':
					snprintf(dp, sizeof(buf) - (dp - buf), "%s",
					         S(ctx->user));
					dp += strlen(dp);
					break;

				/* %s: service */
				case 's':
					snprintf(dp, sizeof(buf) - (dp - buf), "%s",
					         S(ctx->svc));
					dp += strlen(dp);
					break;

				/* %r: remote host */
				case 'r':
					snprintf(dp, sizeof(buf) - (dp - buf), "%s",
					         S(ctx->rhost));
					dp += strlen(dp);
					break;

				/* %h: local host */
				case 'h':
					snprintf(dp, sizeof(buf) - (dp - buf), "%s",
					         S(ctx->uts.nodename));
					dp += strlen(dp);
					break;

				/* %m: module class */
				case 'm':
					snprintf(dp, sizeof(buf) - (dp - buf), "%s",
					         S(ctx->module));
					dp += strlen(dp);
					break;

				default:
					*dp++ = '%';
					*dp++ = *sp;
					break;
			}
			sp++;
		}
		else {
			*dp++ = *sp++;
		}
	}
	*dp = '\0';

	return strdup(buf);
}
