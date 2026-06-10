/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "srun_config.h"

#include "srun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/wait.h>

#if defined __APPLE__
#include <readpassphrase.h>
#elif defined(__has_include) && __has_include(<bsd/readpassphrase.h>)
#include <bsd/readpassphrase.h>
#else
#warning "libbsd not found, will use potentially insecure fallback implementation"
#define RPP_ECHO_ON 1
#define RPP_ECHO_OFF 0
static inline char *readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags) {
  if (!bufsiz) {
    errno = EINVAL;
    return NULL;
  }

  buf[0] = '\0';
  if (flags & RPP_ECHO_ON) {
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (!fgets(buf, bufsiz, stdin)) {
      return NULL;
    }
    buf[strcspn(buf, "\n")] = '\0';
  } else {
    char *pass = getpass(prompt);
    if (!pass) {
      return NULL;
    }

    strncpy(buf, pass, bufsiz - 1);
    buf[bufsiz - 1] = '\0';
    memset(pass, 0, strlen(pass));
  }
  return buf;
}
#endif

#ifdef SRUN_GIT_HASH
#define GIT_HASH_STR " (" SRUN_GIT_HASH ")"
#else
#define GIT_HASH_STR ""
#endif

enum {
  ACTION_LOGIN,
  ACTION_LOGOUT,
};

static const char *prog_name;

static struct {
  char *base_url;
  char *username;
  char *password;

  char *cacert_path;
  size_t cacert_len;

  char *ip;
  char *if_name;

  int ac_id;

  enum srun_verbosity verbosity;
} opts;

static void print_version(void) {
  puts("Version: srun " SRUN_VERSION GIT_HASH_STR ", built on " SRUN_BUILD_TIME);
}

static void print_help(void) {
  print_version();
  printf("\nUsage: %s <login | logout> [options]\n", prog_name);
  puts("Options:");
  puts("  -h, --help");
  puts("          print this help message and exit");
  puts("  -b, --base-url=URL");
  puts("          the authentication server base URL");
  puts("  -u, --username=USERNAME");
  puts("          username for authentication");
  puts("  -p, --password=PASSWORD");
  puts("          password for authentication");
  puts("          if not specified, the program will ask interactively");
  puts("          password without username is not allowed and is ignored");
  puts("  -a, --ac-id=ID");
  puts("          specify ac_id for the request");
  puts("          if not specified, try to guess from the authentication server");
  puts("  -i, --ip=IP");
  puts("          use IP as the client IP");
  puts("  -I, --interface=INTERFACE");
  puts("          bind request to specified network interface");
  puts("          libcurl backend supports this option");
  puts("  -c, --cacert=FILE");
  puts("          specify the CA certificate file for authentication server");
  puts("  -q, --quiet");
  puts("          suppress standard output");
  puts("  -v, --verbose");
  puts("          enable verbose output to stderr");
  puts("          can be specified multiple times to increase verbosity, maximum is 2");
  puts("  -V, --version");
  puts("          print version information and exit");
}

static void parse_opt(int argc, char *const *argv) {
  static const struct option LONG_OPTS[] = {
      {"help", no_argument, NULL, 'h'},
      {"base-url", required_argument, NULL, 'b'},
      {"username", required_argument, NULL, 'u'},
      {"password", required_argument, NULL, 'p'},
      {"ac-id", required_argument, NULL, 'a'},
      {"ip", required_argument, NULL, 'i'},
      {"interface", required_argument, NULL, 'I'},
      {"cacert", required_argument, NULL, 'c'},
      {"quiet", no_argument, NULL, 'q'},
      {"verbose", no_argument, NULL, 'v'},
      {"version", no_argument, NULL, 'V'},
      {0},
  };
  static const char SHORT_OPTS[] = "hb:u:p:a:i:I:c:qvV";

  int c;
  while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
    switch (c) {
      case 'h':
        print_help();
        exit(EXIT_SUCCESS);
      case 'b':
        free(opts.base_url);
        opts.base_url = strdup(optarg);
        break;
      case 'u':
        free(opts.username);
        opts.username = strdup(optarg);
        break;
      case 'p':
        if (opts.password) {
          memset(opts.password, 0, strlen(opts.password));
        }
        free(opts.password);
        opts.password = strdup(optarg);
        break;
      case 'a':
        opts.ac_id = (int)strtol(optarg, NULL, 0);
        break;
      case 'i':
        free(opts.ip);
        opts.ip = strdup(optarg);
        break;
      case 'I':
        free(opts.if_name);
        opts.if_name = strdup(optarg);
        break;
      case 'c':
        free(opts.cacert_path);
        opts.cacert_path = strdup(optarg);
        break;
      case 'q':
        opts.verbosity = SRUN_VERBOSITY_SILENT;
        break;
      case 'v':
        if (opts.verbosity < SRUN_VERBOSITY_VERBOSE) {
          opts.verbosity = SRUN_VERBOSITY_VERBOSE;
        } else {
          opts.verbosity = SRUN_VERBOSITY_DEBUG;
        }
        break;
      case 'V':
        print_version();
        exit(EXIT_SUCCESS);
      default:
        fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
        exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char **argv) {
  int retval = EXIT_FAILURE;
  prog_name = basename(argv[0]);

  if (argc == 1) {
    goto no_action;
  }

  // provide default values
  opts.verbosity = SRUN_VERBOSITY_NORMAL;
  opts.ac_id = SRUN_AC_ID_GUESS;

  const char *action_str = argv[1];

  parse_opt(argc, argv);

  if (opts.verbosity == SRUN_VERBOSITY_SILENT && freopen("/dev/null", "w", stdout) == NULL) {
    fprintf(stderr, "Failed to redirect stdout to /dev/null: %s\n", strerror(errno));
    goto exit_cleanup;
  }

  int action;
  if (strcmp(action_str, "login") == 0) {
    action = ACTION_LOGIN;
  } else if (strcmp(action_str, "logout") == 0) {
    action = ACTION_LOGOUT;
  } else {
    fprintf(stderr, "Invalid action: %s\n", action_str);
no_action:
    fprintf(stderr, "Please specify action: login or logout.\n");
help_guide:
    fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
    goto exit_cleanup;
  }

  if (!(opts.base_url && opts.base_url[0])) {
    fprintf(stderr, "Missing fields for %s.\n", action_str);
    goto help_guide;
  }

  if (!opts.username || opts.username[0] == '\0') {
    // can't set password without username
    free(opts.password);
    opts.password = NULL;

    char rpp_buffer[512];
    readpassphrase("Username: ", rpp_buffer, sizeof rpp_buffer, RPP_ECHO_ON);
    opts.username = strdup(rpp_buffer);
  }

  int (*action_func)(srun_handle) = NULL;
  const char *action_name = NULL;

  if (action == ACTION_LOGIN) {
    if (!opts.password || opts.password[0] == '\0') {
      char rpp_buffer[512];
      readpassphrase("Password: ", rpp_buffer, sizeof rpp_buffer, RPP_ECHO_OFF);
      opts.password = strdup(rpp_buffer);
    }
    action_func = srun_login;
    action_name = "in";
  } else {
    action_func = srun_logout;
    action_name = "out";
  }

  srun_config config = {
      .base_url = opts.base_url,
      .username = opts.username,
      .password = opts.password,

      .cacert_path = opts.cacert_path,
      .cacert_pem = NULL,
      .cacert_len = opts.cacert_len,

      .ip = opts.ip,
      .if_name = opts.if_name,

      .ac_id = opts.ac_id,
      .verbosity = opts.verbosity,

      .user_data = NULL,
  };

  srun_handle handle = srun_create(&config);

  retval = action_func(handle);
  if (retval == SRUNE_OK) {
    printf("Successfully logged %s.\n", action_name);
  } else {
    printf("Log%s failed: error %d\n", action_name, retval);
    if (retval == SRUNE_SYSTEM && errno) {
      perror(prog_name);
    }
  }

  retval = retval == SRUNE_OK ? EXIT_SUCCESS : EXIT_FAILURE;

  srun_cleanup(handle);
  handle = NULL;

exit_cleanup:
  if (opts.password) {
    memset(opts.password, 0, strlen(opts.password));
  }

  free(opts.base_url);
  free(opts.username);
  free(opts.password);
  free(opts.cacert_path);
  free(opts.ip);
  free(opts.if_name);
  memset(&opts, 0, sizeof opts);

  return retval;
}
