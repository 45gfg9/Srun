/* Copyright © 2023 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "srun.h"
#include "srun_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <curl/curl.h>

#if defined __APPLE__
#include <readpassphrase.h>
#else
#include <bsd/readpassphrase.h>
#include <bsd/string.h>
#endif

enum {
  ACTION_LOGIN,
  ACTION_LOGOUT,
};

static const char *prog_name;

struct {
  char auth_server[64];

  char client_ip[64];

  char username[64];

  char password[128];

  char *cert_pem;

  int ac_id;

  // verbosity:
  // -2: completely silent, no error message
  // -1: silent, only print error message
  // 0: normal, print only status message
  // 1: verbose, print debug message
  // 2: very verbose, enable libcurl verbose output
  int verbosity;
} cli_args;

static const char *pathToFilename(const char *path) {
  const char *p = strrchr(path, '/');
  return p ? p + 1 : path;
}

static void print_version(void) {
  printf("Version: %s " SRUN_VERSION " (" SRUN_GIT_HASH "), Built on " SRUN_BUILD_TIME ".\n", prog_name);
  puts("Configured with:");
#ifdef SRUN_CONF_AC_ID
  printf("  ac-id: %d\n", SRUN_CONF_AC_ID);
#endif
#ifdef SRUN_CONF_AUTH_URL
  puts("  Auth server URL: " SRUN_CONF_AUTH_URL);
#endif
#ifdef SRUN_CONF_DEFAULT_USERNAME
  puts("  Default username: " SRUN_CONF_DEFAULT_USERNAME);
#endif
#ifdef SRUN_CONF_DEFAULT_PASSWORD
  puts("  Default password set.");
#endif
#ifdef SRUN_CONF_DEFAULT_CLIENT_IP
  puts("  Default client IP: " SRUN_CONF_DEFAULT_CLIENT_IP);
#endif
#ifdef SRUN_CONF_DEFAULT_CERT
  // TODO show certificate info
  puts("  Default certificate set.");
#endif
}

static void print_help(void) {
  print_version();
  printf("Usage: %s <login | logout> [options]\n", prog_name);
  puts("Options:");
  puts("  -h, --help");
  puts("          print this help message and exit");
  puts("  -f, --config=FILE");
  puts("          read options from FILE in JSON format");
  puts("  -s, --auth-server=HOST");
  puts("          use HOST as the authentication server");
  puts("  -u, --username=USERNAME");
  puts("          use USERNAME to login");
  puts("  -p, --password=PASSWORD");
  puts("          use PASSWORD to login");
  puts("          If not specified, the program will ask interactively");
  puts("  -i, --client-ip=IP");
  puts("          use IP as the client IP");
  puts("  -a, --ac-id=ID");
  puts("          use ID as the AC-ID");
  puts("  -c, --cert-file=FILE");
  puts("          use FILE as the PEM certificate");
  puts("  -q, --quiet");
  puts("          print only error message");
  puts("          -qq to suppress all output");
  puts("  -v, --verbose[=LEVEL]");
  puts("          -vv is the same as --verbose=2");
  puts("          Level 1: print debug message");
  puts("          Level 2: also print libcurl verbose message");
  puts("  -V, --version");
  puts("          print version information and exit");
}

static void parse_config(const char *path) {
  puts("config");
  // TODO
}

static char *read_cert_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    perror(prog_name);
    return NULL;
  }
  free(cli_args.cert_pem);

  // read file contents
  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  fseek(f, 0, SEEK_SET);
  cli_args.cert_pem = malloc(size + 1);
  if (!cli_args.cert_pem) {
    perror(prog_name);
    fclose(f);
    return NULL;
  }
  if (fread(cli_args.cert_pem, 1, size, f) != size) {
    perror(prog_name);
    fclose(f);
    free(cli_args.cert_pem);
    cli_args.cert_pem = NULL;
    return NULL;
  }

  if (!strstr(cli_args.cert_pem, "-----BEGIN CERTIFICATE-----")) {
    fprintf(stderr, "Invalid PEM certificate: %s\n", path);
    free(cli_args.cert_pem);
    cli_args.cert_pem = NULL;
  }

  return cli_args.cert_pem;
}

static void parse_opt(int argc, char *const *argv) {
  static const struct option LONG_OPTS[] = {
      {"help", no_argument, NULL, 'h'},
      {"config", required_argument, NULL, 'f'},
      {"auth-server", required_argument, NULL, 's'},
      {"username", required_argument, NULL, 'u'},
      {"password", required_argument, NULL, 'p'},
      {"ac-id", required_argument, NULL, 'a'},
      {"client-ip", required_argument, NULL, 'i'},
      {"cert-file", required_argument, NULL, 'c'},
      {"quiet", no_argument, NULL, 'q'},
      {"verbose", optional_argument, NULL, 'v'},
      {"version", no_argument, NULL, 'V'},
      {},
  };
  static const char *const SHORT_OPTS = "hf:s:u:p:a:i:c:qvV";

  int c;
  while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
    switch (c) {
      case 'h':
        print_help();
        exit(0);
      case 'f':
        parse_config(optarg);
        break;
      case 's':
        strlcpy(cli_args.auth_server, optarg, sizeof cli_args.auth_server);
        break;
      case 'u':
        strlcpy(cli_args.username, optarg, sizeof cli_args.username);
        break;
      case 'p':
        strlcpy(cli_args.password, optarg, sizeof cli_args.password);
        break;
      case 'a':
        cli_args.ac_id = (int)strtol(optarg, NULL, 10);
        break;
      case 'i':
        strlcpy(cli_args.client_ip, optarg, sizeof cli_args.client_ip);
        break;
      case 'c':
        free(cli_args.cert_pem);
        cli_args.cert_pem = read_cert_file(optarg);
        break;
      case 'q':
        --cli_args.verbosity;
        break;
      case 'v':
        if (optarg) {
          cli_args.verbosity = (int)strtol(optarg, NULL, 10);
        } else {
          ++cli_args.verbosity;
        }
        break;
      case 'V':
        print_version();
        exit(0);
    }
  }
}

static int perform_login(srun_handle handle) {
  if (cli_args.username[0] == 0) {
    // can't set password without username
    memset(cli_args.password, 0, sizeof cli_args.password);

    readpassphrase("Username: ", cli_args.username, sizeof cli_args.username, RPP_ECHO_ON);
    srun_setopt(handle, SRUNOPT_USERNAME, cli_args.username);
  }

  if (cli_args.password[0] == 0) {
    readpassphrase("Password: ", cli_args.password, sizeof cli_args.password, RPP_ECHO_OFF);
    srun_setopt(handle, SRUNOPT_PASSWORD, cli_args.password);
  }

  int result = srun_login(handle);
  if (result == SRUNE_OK && cli_args.verbosity >= 0) {
    fprintf(stderr, "Successfully logged in.\n");
  } else if (result != SRUNE_OK && cli_args.verbosity >= -1) {
    fprintf(stderr, "Login failed: error %d\n", result);
  }
  return result;
}

static int perform_logout(srun_handle handle) {
  int result = srun_logout(handle);
  if (result == SRUNE_OK && cli_args.verbosity > -1) {
    fprintf(stderr, "Successfully logged out.\n");
  } else if (result != SRUNE_OK && cli_args.verbosity > -2) {
    fprintf(stderr, "Logout failed: error %d\n", result);
  }
  return result;
}

int main(int argc, char **argv) {
  srand(time(NULL));

  // provide default values
#ifdef SRUN_CONF_AC_ID
  cli_args.ac_id = SRUN_CONF_AC_ID;
#endif
#ifdef SRUN_CONF_AUTH_URL
  strlcpy(cli_args.auth_server, SRUN_CONF_AUTH_URL, sizeof cli_args.auth_server);
#endif
#ifdef SRUN_CONF_DEFAULT_USERNAME
  strlcpy(cli_args.username, SRUN_CONF_DEFAULT_USERNAME, sizeof cli_args.username);
#endif
#ifdef SRUN_CONF_DEFAULT_PASSWORD
  strlcpy(cli_args.password, SRUN_CONF_DEFAULT_PASSWORD, sizeof cli_args.password);
#endif
#ifdef SRUN_CONF_DEFAULT_CERT
  cli_args.cert_pem = malloc(strlen(SRUN_CONF_DEFAULT_CERT) + 1);
  strcpy(cli_args.cert_pem, SRUN_CONF_DEFAULT_CERT);
#endif
#ifdef SRUN_CONF_DEFAULT_CLIENT_IP
  strlcpy(cli_args.client_ip, SRUN_CONF_DEFAULT_CLIENT_IP, sizeof cli_args.client_ip);
#endif

  prog_name = pathToFilename(argv[0]);

  if (argc == 1) {
    goto no_action;
  }
  const char *action_str = argv[1];

  parse_opt(argc, argv);

  int action;
  int all_args_present;
  if (strcmp(action_str, "login") == 0) {
    action = ACTION_LOGIN;
    all_args_present = cli_args.auth_server[0] && cli_args.ac_id;
  } else if (strcmp(action_str, "logout") == 0) {
    action = ACTION_LOGOUT;
    all_args_present = cli_args.auth_server[0];
  } else {
    fprintf(stderr, "Invalid action: %s\n", action_str);
no_action:
    fprintf(stderr, "Please specify action: login or logout.\n");
    fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
    return -1;
  }

  if (!all_args_present) {
    fprintf(stderr, "Missing fields for %s.\n", action_str);
    fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
    return -1;
  }

  curl_global_init(CURL_GLOBAL_ALL);
  srun_handle handle = srun_create();

  srun_setopt(handle, SRUNOPT_AUTH_SERVER, cli_args.auth_server);
  srun_setopt(handle, SRUNOPT_USERNAME, cli_args.username);
  srun_setopt(handle, SRUNOPT_PASSWORD, cli_args.password);
  srun_setopt(handle, SRUNOPT_AC_ID, cli_args.ac_id);
  srun_setopt(handle, SRUNOPT_CLIENT_IP, cli_args.client_ip);
  srun_setopt(handle, SRUNOPT_SERVER_CERT, cli_args.cert_pem);
  srun_setopt(handle, SRUNOPT_VERBOSITY, cli_args.verbosity);

  int retval = -1;
  if (action == ACTION_LOGIN) {
    retval = perform_login(handle) != SRUNE_OK;
  } else if (action == ACTION_LOGOUT) {
    retval = perform_logout(handle) != SRUNE_OK;
  }

  srun_cleanup(handle);
  handle = NULL;

  free(cli_args.cert_pem);
  cli_args.cert_pem = NULL;
  curl_global_cleanup();

  memset(&cli_args, 0, sizeof cli_args);

  return retval;
}
