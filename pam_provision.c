#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <sys/utsname.h>

#define NAME "pam_provision"

/* The context structure accumulates information about the context of
 * the PAM event so that logging and other utility code can cite it.  */
struct context {
	char *user;
	char *svc;
	char *rhost;
	char *module;
	struct utsname uts;
	int log;
};


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
get_context(pam_handle_t *pamh, char *module)
{
	struct context *ctx;

	ctx = malloc(sizeof(struct context));
	memset(ctx, 0, sizeof(struct context));

	uname(&ctx->uts);
	pam_get_user(pamh, &ctx->user, NULL);
	pam_get_item(pamh, PAM_SERVICE, (void **)&ctx->svc);
	pam_get_item(pamh, PAM_RHOST, (void **)&ctx->rhost);
	ctx->module = strdup(module);
	ctx->log = LOG_AUTH;

	if (ctx->user == NULL)
		ctx->user = "(unknown)";
	if (ctx->svc == NULL)
		ctx->svc = "(unknown)";
	if (ctx->rhost == NULL)
		ctx->rhost = "(local)";

	return ctx;
}


/* Release a context structure cleanly. */
void
free_context(struct context *ctx)
{
	if (ctx->module)
		free(ctx->module);
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
	         NAME, ctx->module ? ctx->module : "unknown", fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, vp);
	va_end(vp);

	syslog(ctx->log|level, msgbuf);
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


/* Call the provisioner script (back end for any pam hook) */
int
provision(struct context *ctx, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char **xargv = NULL;
	int i, j;
	int status = PAM_SUCCESS;

	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "log=", 4)) {
			int log;
			log = get_syslog((char *)&argv[i][4]);
			if (log == -1) {
				msg(ctx, LOG_WARNING, "unknown log facility %s", &argv[i][4]);
				return PAM_SERVICE_ERR;
			}
			else {
				ctx->log = log;
			}
		}
		else if (!strncmp(argv[i], "exec=", 5)) {
			xargv = malloc(sizeof(char *) * (argc - i + 1));
			xargv[0] = expand(ctx, (char *)&argv[i][5]);
			for (i++, j = 1; i < argc; i++, j++)
				xargv[j] = expand(ctx, (char *)argv[i]);
			xargv[j] = NULL;
			break;
		}
		else {
			msg(ctx, LOG_WARNING, "unknown parameter %s", argv[i]);
			return PAM_SERVICE_ERR;
		}
	}

	if (xargv) {
		status = sh(ctx, xargv);
		for (i = 0; xargv[i]; i++)
			free(xargv[i]);
	}

	free_context(ctx);
	return status;
}


/* PAM hook for SESSION opening:
 * other session required pam_provision.so exec=script.py %u
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct context *ctx = get_context(pamh, "session-open");
	int result;

	msg(ctx, LOG_INFO, "%s@%s: open session for %s@%s",
	    ctx->svc, ctx->uts.nodename, ctx->user, ctx->rhost);
	result = provision(ctx, pamh, flags, argc, argv);
	free_context(ctx);
	return result;
}


/* PAM hook for SESSION closing:
 * other session required pam_provision.so exec=script.py %u
 */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct context *ctx = get_context(pamh, "session-close");
	int result;

	msg(ctx, LOG_INFO, "%s@%s: close session for %s@%s",
	    ctx->svc, ctx->uts.nodename, ctx->user, ctx->rhost);
	result = provision(ctx, pamh, flags, argc, argv);
	free_context(ctx);
	return result;
}


/* PAM hook for ACCOUNT management:
 * other account required pam_provision.so exec=script.py %u
 */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct context *ctx = get_context(pamh, "account");
	int result;

	msg(ctx, LOG_INFO, "%s@%s: acct mgmt for %s@%s",
	    ctx->svc, ctx->uts.nodename, ctx->user, ctx->rhost);
	result = provision(ctx, pamh, flags, argc, argv);
	free_context(ctx);
	return result;
}
