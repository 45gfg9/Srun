#ifndef __SRUN_LOGIN_H__
#define __SRUN_LOGIN_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct srun_context {
  // Username; must be set
  char *username;
  // Password; must be set
  char *password;
  // Auth server
  char *auth_server;
  // Client IP
  char *client_ip;
  // ac_id
  int ac_id;

  // server ctx_time
  long ctx_time;
  // callback random
  int randnum;
  // verbosity
  int verbose;
} srun_context;

typedef enum srun_option {
  SRUNOPT_USERNAME,
  SRUNOPT_PASSWORD,
  SRUNOPT_AUTH_SERVER,
  SRUNOPT_CLIENT_IP,
  SRUNOPT_AC_ID,
  SRUNOPT_VERBOSE,
} srun_option;

#define SRUNE_OK 0
#define SRUNE_NETWORK -1
#define SRUNE_INVALID_CTX -2

/**
 * Initialize Srun context. The same context must NOT be initialized twice; or memory leak.
 *
 * @param context An uninitialized context.
 */
void srun_init(srun_context *context);

void srun_setopt(srun_context *context, srun_option option, ...);
/**
 * Set option of Srun context.
 *
 * @param context Srun context; must be initialized
 * @param option
 * @param value
 */
#define srun_setopt(context, option, value) srun_setopt(context, option, value)
/**
 * Perform login. The username, password, auth server and ac_id must be set.
 *
 * @param context Srun context; must be initialized
 * @return 0 if logged in successfully or device already online; gateway error code or defined error code otherwise
 */
int srun_login(srun_context *context);
/**
 * Logout from this session.
 *
 * Auth server needs to be set; other fields are not required
 *
 * @param context Srun context; must be initialized first
 * @return 0 if logged out successfully; -1 if network error
 */
int srun_logout(srun_context *context);
/**
 * Release all allocated resources held by this context
 *
 * @param context Srun context
 */
void srun_cleanup(srun_context *context);

#ifdef __cplusplus
}
#endif

#endif
