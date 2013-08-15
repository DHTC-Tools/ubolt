#include <pwd.h>
#include <stdbool.h> /* bool type */

void subst(char **inp, char *find, char *replace, bool canfree, void (*filter)(char *p, int len));

void pass_capitalize(char *p, int len);
void pass_lowercase(char *p, int len);
void pass_uppercase(char *p, int len);

void filter_passwd(struct passwd *pwd, char *buffer, size_t buflen);
