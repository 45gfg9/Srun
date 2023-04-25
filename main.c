#include "srun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#ifndef SRUN_LOGIN_AUTH_URL
#define SRUN_LOGIN_AUTH_URL NULL
#endif

#ifndef SRUN_LOGIN_AC_ID
#define SRUN_LOGIN_AC_ID 0
#endif

int main() {
  srand(time(NULL));

  srun_context ctx;
  srun_init(&ctx);

  fprintf(stderr, "Username: ");
  char username[32];
  fgets(username, sizeof username, stdin);
  username[strlen(username) - 1] = 0;

  char *passwd = getpass("Password: ");

  srun_setopt(&ctx, SRUNOPT_USERNAME, username);
  srun_setopt(&ctx, SRUNOPT_AUTH_SERVER, SRUN_LOGIN_AUTH_URL);
  srun_setopt(&ctx, SRUNOPT_AC_ID, SRUN_LOGIN_AC_ID);
  srun_setopt(&ctx, SRUNOPT_PASSWORD, passwd);
  srun_setopt(&ctx, SRUNOPT_VERBOSE, 1);
  memset(passwd, 0, strlen(passwd));

  curl_global_init(CURL_GLOBAL_ALL);

  int result = srun_login(&ctx);
  printf("login result: %d\n", result);

  srun_cleanup(&ctx);

  curl_global_cleanup();
}
