#ifndef __SRUN_LOGIN_H__
#define __SRUN_LOGIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <time.h>

typedef struct srun_login_context {
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

  // internal fields

  // server chall
  char *chall;
  // server time
  time_t server_time;
  // callback random
  int randnum;
} srun_login_context;

typedef enum srun_login_option {
  SRLOPT_USERNAME,
  SRLOPT_PASSWORD,
  SRLOPT_AUTH_SERVER,
  SRLOPT_CLIENT_IP,
  SRLOPT_AC_ID,
} srun_login_option;

void srun_login_init(srun_login_context *context);
void srun_login_setopt(srun_login_context *context, srun_login_option option, ...);
void srun_login_perform(srun_login_context *context);
void srun_logout_perform(srun_login_context *context);
void srun_login_cleanup(srun_login_context *context);

#define srun_login_setopt(context, option, value) srun_login_setopt(context, option, value)

#ifdef __cplusplus
}
#endif

#endif
