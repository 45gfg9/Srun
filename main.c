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
#endif

// verbosity:
// -2: completely silent, no error message
// -1: silent, only print error message
// 0: normal, print only status message
// 1: verbose, print debug message
// 2: very verbose, print HTTP request and response
static int verbosity;

static const char *prog_name;

static char *cert_pem;

static void print_version(void) {
  printf("Version: %s " SRUN_VERSION " (" SRUN_GIT_HASH "), Built on " SRUN_BUILD_TIME "\n", prog_name);
}

static void print_help(void) {
  print_version();
  printf("Usage: %s login [options]\n", prog_name);
  printf("       %s logout [options]\n", prog_name);
  printf("Options:\n");
  printf("  -h, --help\n");
  printf("          print this help message and exit\n");
  printf("  -f, --config=FILE\n");
  printf("          read options from FILE in JSON format\n");
  printf("  -s, --auth-server=HOST\n");
  printf("          use HOST as the authentication server\n");
  printf("  -u, --username=USERNAME\n");
  printf("          use USERNAME to login\n");
  printf("  -p, --password=PASSWORD\n");
  printf("          use PASSWORD to login\n");
  printf("  -a, --ac-id=ID\n");
  printf("          use ID as the AC-ID\n");
  printf("  -c, --cert-file=FILE\n");
  printf("          use FILE as the PEM certificate\n");
  printf("  -q, --quiet\n");
  printf("          print only error message\n");
  printf("          -qq to suppress all output\n");
  printf("  -v, --verbose[=LEVEL]\n");
  printf("          -vv is the same as --verbose=2\n");
  printf("          Level 1: print debug message\n");
  printf("          Level 2: also print HTTP request and response\n");
  printf("  -V, --version\n");
  printf("          print version information and exit\n");
}

static void parse_config(srun_handle handle, const char *path) {
  printf("config\n");
  // TODO
}

static char *read_cert_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    perror(prog_name);
    return NULL;
  }
  free(cert_pem);

  // read file contents
  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  fseek(f, 0, SEEK_SET);
  cert_pem = malloc(size + 1);
  if (!cert_pem) {
    perror(prog_name);
    fclose(f);
    return NULL;
  }
  if (fread(cert_pem, 1, size, f) != size) {
    perror(prog_name);
    fclose(f);
    free(cert_pem);
    cert_pem = NULL;
    return NULL;
  }

  if (!strstr(cert_pem, "-----BEGIN CERTIFICATE-----")) {
    fprintf(stderr, "Invalid PEM certificate: %s\n", path);
    free(cert_pem);
    cert_pem = NULL;
  }

  return cert_pem;
}

static void parse_opt(srun_handle handle, int argc, char *const *argv) {
  static const struct option LONG_OPTS[] = {
      {"help", no_argument, NULL, 'h'},
      {"config", required_argument, NULL, 'f'},
      {"auth-server", required_argument, NULL, 's'},
      {"username", required_argument, NULL, 'u'},
      {"password", required_argument, NULL, 'p'},
      {"ac-id", required_argument, NULL, 'a'},
      {"cert-file", required_argument, NULL, 'c'},
      {"quiet", no_argument, NULL, 'q'},
      {"verbose", optional_argument, NULL, 'v'},
      {"version", no_argument, NULL, 'V'},
      {},
  };
  static const char *const SHORT_OPTS = "hf:s:u:p:a:c:qvV";

  // TODO
  int c;
  while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
    printf("c = %c\n", c);
    printf("optind = %d; optopt = %d\n", optind, optopt);
    printf("optarg = %s\n", optarg);

    switch (c) {
      case 'h':
        print_help();
        exit(0);
      case 'f':
        parse_config(handle, optarg);
        break;
      case 's':
        printf("auth-server\n");
        srun_setopt(handle, SRUNOPT_AUTH_SERVER, optarg);
        break;
      case 'u':
        printf("username\n");
        srun_setopt(handle, SRUNOPT_USERNAME, optarg);
        break;
      case 'p':
        printf("password\n");
        srun_setopt(handle, SRUNOPT_PASSWORD, optarg);
        break;
      case 'a':
        printf("ac-id\n");
        srun_setopt(handle, SRUNOPT_AC_ID, strtol(optarg, NULL, 10));
        break;
      case 'c':
        printf("cert-file\n");
        free(cert_pem);
        cert_pem = read_cert_file(optarg);
        break;
      case 'q':
        printf("quiet\n");
        --verbosity;
        break;
      case 'v':
        printf("verbose\n");
        if (optarg) {
          verbosity = (int)strtol(optarg, NULL, 10);
        } else {
          ++verbosity;
        }
        break;
      case 'V':
        print_version();
        exit(0);
      default:
        printf("default\n");
        break;
    }
  }
}

static int perform_login(srun_handle handle) {
  if (!handle->username) {
    // it's not right if only the password is provided
    free(handle->password);
    handle->password = NULL;

    fprintf(stderr, "Username: ");
    char username[128];
    fgets(username, sizeof username, stdin);
    username[strlen(username) - 1] = 0;
    srun_setopt(handle, SRUNOPT_USERNAME, username);
  }

  if (!handle->password) {
    char passwd[128];
    readpassphrase("Password: ", passwd, sizeof passwd, RPP_ECHO_OFF);
    srun_setopt(handle, SRUNOPT_PASSWORD, passwd);
    memset(passwd, 0, strlen(passwd));
  }

  // srun_setopt(handle, SRUNOPT_VERBOSE, 1);

  // TODO better logging
  int result = srun_login(handle);
  if (result == SRUNE_OK && verbosity > -1) {
    fprintf(stderr, "Successfully logged in.\n");
  } else if (result != SRUNE_OK && verbosity > -2) {
    fprintf(stderr, "Login failed: error %d\n", result);
  }
  return result;
}

static int perform_logout(srun_handle handle) {
  int result = srun_logout(handle);
  if (result == SRUNE_OK && verbosity > -1) {
    fprintf(stderr, "Successfully logged out.\n");
  } else if (result != SRUNE_OK && verbosity > -2) {
    fprintf(stderr, "Logout failed: error %d\n", result);
  }
  return result;
}

int main(int argc, char *const *argv) {
  srand(time(NULL));

  int retval = 0;

  prog_name = argv[0];
  if (argc == 1) {
    fprintf(stderr, "Please specify login or logout\n");
    return 1;
  }

  curl_global_init(CURL_GLOBAL_ALL);
  srun_handle handle = srun_create();

  const char *action = argv[1];
  parse_opt(handle, argc, argv);

  // provide default values
#ifdef SRUN_CONF_AC_ID
  if (handle->ac_id == 0) {
    srun_setopt(handle, SRUNOPT_AC_ID, SRUN_CONF_AC_ID);
  }
#endif
#ifdef SRUN_CONF_AUTH_URL
  if (handle->auth_server == NULL) {
    srun_setopt(handle, SRUNOPT_AUTH_SERVER, SRUN_CONF_AUTH_URL);
  }
#endif
#ifdef SRUN_CONF_DEFAULT_USERNAME
  if (handle->username == NULL) {
    srun_setopt(handle, SRUNOPT_USERNAME, SRUN_CONF_DEFAULT_USERNAME);
  }
#endif
#ifdef SRUN_CONF_DEFAULT_PASSWORD
  if (handle->password == NULL) {
    srun_setopt(handle, SRUNOPT_PASSWORD, SRUN_CONF_DEFAULT_PASSWORD);
  }
#endif
#ifdef SRUN_CONF_DEFAULT_CERT
  if (handle->server_cert == NULL) {
    srun_setopt(handle, SRUNOPT_SERVER_CERT, SRUN_CONF_DEFAULT_CERT);
  }
#endif

  if (!strcmp(action, "login")) {
    retval = perform_login(handle) != SRUNE_OK;
  } else if (!strcmp(action, "logout")) {
    retval = perform_logout(handle) != SRUNE_OK;
  } else {
    fprintf(stderr, "Please specify login or logout\n");
    retval = 1;
  }

  srun_cleanup(handle);
  handle = NULL;

  free(cert_pem);
  cert_pem = NULL;
  curl_global_cleanup();

  return retval;
}
