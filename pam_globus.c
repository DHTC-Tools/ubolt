/*
 * pam_globus :-
 * 
 * authenticate a PAM-based system against globus online
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
//#include <errno.h>
//#include <fcntl.h>
//#include <unistd.h>
//#include <signal.h>
//#include <sys/types.h>
//#include <sys/wait.h>
//#include <sys/socket.h>
//#include <syslog.h>

// Needed in case code is compiled statically
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "globus.h"
#include "util.h"

#define NAME "pam_globus"
#define NEXUSBASE "https://nexus.api.globusonline.org"

typedef struct settings_t {
	struct context *ctx;
	bool autofree;
	bool use_first;
	bool try_first;
} settings_t;

/* Option parser for pam_globus */
settings_t *
get_settings(pam_handle_t *pamh, char *phase, settings_t *s)
{
	if (s == NULL) {
		s = malloc(sizeof(struct settings_t));
		s->autofree = true;  /* auto-created; must be auto-freed */
	}

	s->use_first = false;
	s->try_first = false;

	s->ctx = get_context(pamh, NAME, phase);

	return s;
}

void
free_settings(settings_t *settings)
{
	bool autofree = settings->autofree;

	if (settings->ctx)
		free_context(settings->ctx);
	memset(settings, 0, sizeof(settings_t));
	if (autofree)
		free(settings);
}


int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* PAM hook for AUTH
 * other auth required pam_globus.so
 */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	settings_t *settings = get_settings(pamh, "auth", NULL);
	int result = PAM_AUTH_ERR;  /* Default to failure in case of bugs */
	int rc;
	bool already = false;
	const char *user, *pass;

	msg(settings->ctx, LOG_INFO, "%s@%s: authenticate %s@%s",
	    settings->ctx->svc, settings->ctx->uts.nodename, settings->ctx->user, settings->ctx->rhost);

	rc = pam_get_user(pamh, &user, "Globus Username: ");
	if (rc != PAM_SUCCESS) {
		msg(settings->ctx, LOG_ERR, "%s@%s: cannot obtain username",
		    settings->ctx->svc, settings->ctx->uts.nodename);
		return rc;
	}

	rc = pam_set_item(pamh, PAM_USER, user);
	if (rc != PAM_SUCCESS) {
		msg(settings->ctx, LOG_ERR, "%s@%s: cannot set username",
		    settings->ctx->svc, settings->ctx->uts.nodename);
		return PAM_AUTHINFO_UNAVAIL;
	}

	//msg(settings->ctx, LOG_INFO, "checkpoint 1");

	/* If options request using inherited authentication tokens: */
	if (settings->use_first || settings->try_first) {
		/* Get current authentication token, if present. */
		pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pass);

	//msg(settings->ctx, LOG_INFO, "checkpoint 2");

		/* If authtok exists, try to authenticate with the old authtok. */
		if (pass) {
			rc = globus_authenticate(NEXUSBASE, user, pass);
			//msg(settings->ctx, LOG_INFO, "auth: %d", rc);
			if (rc == PAM_SUCCESS)
				return PAM_SUCCESS;
		}

	//msg(settings->ctx, LOG_INFO, "checkpoint 3");

		/* If we required inherited authtoks, fail now. */
		if (settings->use_first)
			return rc;

		already = true;  /* already prompted user */
	}

	//msg(settings->ctx, LOG_INFO, "checkpoint 4");

	/* Prompt for a token and try it. */
	{
		struct pam_message      pmsg, *pmsgp;
		struct pam_response    *resp;
		const struct pam_conv  *conv;

		pmsg.msg_style = PAM_PROMPT_ECHO_OFF;
		pmsg.msg = already ? "Globus Password: " : "Password: ";
		pmsgp = &pmsg;

		//msg(settings->ctx, LOG_INFO, "checkpoint 5");

		rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
		if (rc != PAM_SUCCESS) {
			free_settings(settings);
			return rc;
		}

		//msg(settings->ctx, LOG_INFO, "checkpoint 6");

		conv->conv(1, (const struct pam_message **)&pmsgp, &resp, conv->appdata_ptr);
		if (resp == NULL) {
			free_settings(settings);
			return PAM_CONV_ERR;
		}

		//msg(settings->ctx, LOG_INFO, "checkpoint 7");

		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
			free(resp);
			free_settings(settings);
			return PAM_AUTHTOK_ERR;
		}

		//msg(settings->ctx, LOG_INFO, "checkpoint 8");

		rc = globus_authenticate(NEXUSBASE, user, resp[0].resp);
		//msg(settings->ctx, LOG_INFO, "auth: %d", rc);
		if (rc == PAM_SUCCESS) {
			rc = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
			result = rc;
		}

		//msg(settings->ctx, LOG_INFO, "checkpoint 9");

		resp[0].resp = NULL;
		free(resp);
	}

	//msg(settings->ctx, LOG_INFO, "checkpoint 10");

	free_settings(settings);
	return result;
}

/* PAM hook for SESSION opening:
 * other session required pam_globus.so
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	settings_t *settings = get_settings(pamh, "auth", NULL);
	int result = PAM_SUCCESS;

	msg(settings->ctx, LOG_INFO, "%s@%s: open session for %s@%s",
	    settings->ctx->svc, settings->ctx->uts.nodename, settings->ctx->user, settings->ctx->rhost);
	free_settings(settings);
	return result;
}


/* PAM hook for SESSION closing:
 * other session required pam_globus.so
 */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	settings_t *settings = get_settings(pamh, "auth", NULL);
	int result = PAM_SUCCESS;

	msg(settings->ctx, LOG_INFO, "%s@%s: close session for %s@%s",
	    settings->ctx->svc, settings->ctx->uts.nodename, settings->ctx->user, settings->ctx->rhost);
	free_settings(settings);
	return result;
}


/* PAM hook for ACCOUNT management:
 * other account required pam_globus.so
 */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	settings_t *settings = get_settings(pamh, "auth", NULL);
	int result = PAM_SUCCESS;

	msg(settings->ctx, LOG_INFO, "%s@%s: acct mgmt for %s@%s",
	    settings->ctx->svc, settings->ctx->uts.nodename, settings->ctx->user, settings->ctx->rhost);
	return result;
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          printf("You must change your password using the website!\n");
          return PAM_PERM_DENIED;
}
