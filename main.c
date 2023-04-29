#include "srun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <getopt.h>
#include <curl/curl.h>

#ifndef SRUN_LOGIN_AUTH_URL
#define SRUN_LOGIN_AUTH_URL NULL
#endif

#ifndef SRUN_LOGIN_AC_ID
#define SRUN_LOGIN_AC_ID 0
#endif

static int perform_login() {
  return 0;
}

static int perform_logout() {
  return 0;
}

int main(int argc, char *const *argv) {
  srand(time(NULL));

  srun_handle ctx = srun_create();

  fprintf(stderr, "Username: ");
  char username[128];
  fgets(username, sizeof username, stdin);
  username[strlen(username) - 1] = 0;

  char passwd[128];
  readpassphrase("Password: ", passwd, sizeof passwd, RPP_ECHO_OFF);

  srun_setopt(ctx, SRUNOPT_USERNAME, username);
  srun_setopt(ctx, SRUNOPT_AUTH_SERVER, SRUN_LOGIN_AUTH_URL);
  srun_setopt(ctx, SRUNOPT_AC_ID, SRUN_LOGIN_AC_ID);
  srun_setopt(ctx, SRUNOPT_PASSWORD, passwd);
  srun_setopt(ctx, SRUNOPT_VERBOSE, 1);
  memset(passwd, 0, strlen(passwd));

  curl_global_init(CURL_GLOBAL_ALL);

  int result = srun_login(ctx);
  printf("login result: %d\n", result);

  srun_cleanup(ctx);
  ctx = NULL;

  curl_global_cleanup();
}
