/*
curl -v \
	-X POST \
	-H 'Content-Type: application/json' \
	https://nexus.api.globusonline.org/authenticate \
	-d '{"username": "YOU", "password": "REDACTED"}'

gcc -o globus-example globus-example.c -lcurl
./globus-example username
*/

#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>


static size_t
writer(void *ptr, size_t size, size_t nmemb, void *fp)
{
	return size * nmemb;
}


int
main(int argc, char *argv[])
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = NULL;
	char postdata[8*1024];
	char prompt[256];
	char *password;
	long code;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (curl == NULL) {
		curl_global_cleanup();
		return 0;
	}

	snprintf(prompt, sizeof(prompt), "Enter Globus Online password for %s: ", argv[1]); 
	password = getpass(prompt);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	snprintf(postdata, sizeof(postdata), " \
{ \
	\"username\": \"%s\", \
	\"password\": \"%s\" \
}", argv[1], password);


	curl_easy_setopt(curl, CURLOPT_URL, "https://nexus.api.globusonline.org/authenticate");
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);

	/* Provide a read callback so that we don't get JSON output to stdout */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);

	/* Perform the request, res will get the return code */ 
	res = curl_easy_perform(curl);

	/* Check for errors */ 
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	}
	else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (code == 200)
			printf("Success.\n");
		else
			printf("Failure.\n");
	}

	curl_slist_free_all(headers);

	/* always cleanup */ 
	curl_easy_cleanup(curl);

	curl_global_cleanup();

	return 0;
}
