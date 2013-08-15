#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <security/pam_modules.h>

#include "util.h"

#define NAME "pam_provision"


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

	return status;
}


/* PAM hook for SESSION opening:
 * other session required pam_provision.so exec=script.py %u
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct context *ctx = get_context(pamh, NAME, "session-open");
	int result;

	env_setup(pamh, "open_session");
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
	struct context *ctx = get_context(pamh, NAME, "session-close");
	int result;

	env_setup(pamh, "close_session");
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
	struct context *ctx = get_context(pamh, NAME, "account");
	int result;

	env_setup(pamh, "account");
	msg(ctx, LOG_INFO, "%s@%s: acct mgmt for %s@%s",
	    ctx->svc, ctx->uts.nodename, ctx->user, ctx->rhost);
	result = provision(ctx, pamh, flags, argc, argv);
	free_context(ctx);
	return result;
}
