#include <pwd.h>
#include <stdbool.h> /* bool type */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/utsname.h>


/* The context structure accumulates information about the context of
 * the PAM event so that logging and other utility code can cite it.  */
struct context {
	char *name;
	PAM_CONST char *user;
	PAM_CONST char *svc;
	PAM_CONST char *rhost;
	PAM_CONST char *module;
	struct utsname uts;
	int log;
};


void subst(char **inp, char *find, char *replace, bool canfree, void (*filter)(char *p, int len));

void pass_capitalize(char *p, int len);
void pass_lowercase(char *p, int len);
void pass_uppercase(char *p, int len);

void filter_passwd(struct passwd *pwd, char *buffer, size_t buflen);

int get_syslog(char *name);


/* Create and populate a context based on a given PAM handle and
 * module name. */
struct context *get_context(pam_handle_t *pamh, char *name, char *module);

/* Release a context structure cleanly. */
void free_context(struct context *ctx);

/* General syslog front-end */
void msg(struct context *ctx, int level, char *fmt, ...);

/* Set up environment with pam params */
void env_setup(pam_handle_t *pamh, char *type);

/* Execute a program (identified in argv[]) under the given context.
 * Collect output and log it. */
int sh(struct context *ctx, char **argv);

/* Copy the given string, expanding % tokens under context. */
char *expand(struct context *ctx, char *fmt);
