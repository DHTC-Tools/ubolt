/*
 * globus online i9n
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <curl/curl.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "globus.h"

/*
curl -v \
	-X POST \
	-H 'Content-Type: application/json' \
	https://nexus.api.globusonline.org/authenticate \
	-d '{"username": "YOU", "password": "REDACTED"}'
*/

static size_t
writer(void *ptr, size_t size, size_t nmemb, void *fp)
{
	return size * nmemb;
}

/* really need to pass in some error-reporting fptr */

int
globus_authenticate(const char *apibase, const char *user, const char *password)
{

	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	char postdata[8*1024];
	char prompt[256];
	long code;
	char url[8192];
	int rc;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (curl == NULL) {
		curl_global_cleanup();
		return PAM_SYSTEM_ERR;
	}

	headers = curl_slist_append(headers, "Content-Type: application/json");
	snprintf(postdata, sizeof(postdata), " \
{ \
	\"username\": \"%s\", \
	\"password\": \"%s\" \
}", user, password);

	snprintf(url, sizeof(url), "%s/authenticate", apibase);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);

	/* Provide a read callback so that we don't get JSON output to stdout */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);

	/* Perform the request */
	res = curl_easy_perform(curl);

	/* Check for errors */ 
	if (res != CURLE_OK) {
		//fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		rc = PAM_SYSTEM_ERR;;
	}
	else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (code == 200)
			rc = PAM_SUCCESS;
		else
			rc = PAM_AUTHTOK_ERR;
	}

	curl_slist_free_all(headers);

	/* always cleanup */ 
	curl_easy_cleanup(curl);

	curl_global_cleanup();

	return rc;
}
