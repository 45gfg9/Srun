/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef __SRUN_H__
#define __SRUN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

enum srun_verbosity {
  /**
   * @brief Suppress stdout. Errors will be printed to stderr.
   */
  SRUN_VERBOSITY_SILENT = 0,

  /**
   * @brief Print connection status to stdout.
   */
  SRUN_VERBOSITY_NORMAL,

  /**
   * @brief Print detailed connection status to stderr.
   */
  SRUN_VERBOSITY_VERBOSE,

  /**
   * @brief Print all messages and library debug information to stderr.
   */
  SRUN_VERBOSITY_DEBUG,
};

typedef struct srun_context *srun_handle;

typedef struct srun_config {
  const char *base_url; // Authentication server base URL.
  const char *username; // Username for authentication.
  const char *password; // Password for authentication.

  const char *cacert_path; // Path to CA certificate file. If cacert_pem is not NULL, this field is ignored.
  const char *cacert_pem;  // CA certificate in PEM format.
  size_t cacert_len;       // Length of CA certificate PEM. If 0, assume cacert_pem is null-terminated.

  const char *ip;      // Client IP address.
  const char *if_name; // Network interface to use.

  int ac_id; // Portal ac_id.

  enum srun_verbosity verbosity; // Verbosity level.

  void *user_data; // User data pointer.
} srun_config;

enum srun_errno {
  /**
   * Success.
   */
  SRUNE_OK = 0,

  /**
   * Network error.
   */
  SRUNE_NETWORK = -1,

  /**
   * Invalid context (missing fields).
   */
  SRUNE_INVALID_CTX = -2,

  /**
   * System error. See errno.
   */
  SRUNE_SYSTEM = -3,
};

/**
 * Special value indicating that the ac_id is unknown.
 * The library will try to find it automatically.
 */
enum { SRUN_AC_ID_GUESS = 0 };

/**
 * Create a new srun handle. This handle must be freed by `srun_cleanup`.
 *
 * @return A new srun handle
 */
srun_handle srun_create(srun_config *config);

/**
 * Perform login. The username, password and auth server must be set.
 *
 * @param handle srun handle
 * @return SRUNE_OK if logged in successfully or device already online;
 *         gateway error code or library defined error code otherwise
 */
int srun_login(srun_handle handle);

/**
 * Logout from this session.
 *
 * Auth server needs to be set; the certificate must be set too if the server uses HTTPS.
 * No other fields are required.
 *
 * @param handle srun handle
 * @return SRUNE_OK if logged out successfully;
 *         SRUNE_NETWORK if network error
 */
int srun_logout(srun_handle handle);

/**
 * Free all allocated resources held by this handle. You are encouraged to set handle to NULL after this call.
 *
 * @param context srun context
 */
void srun_cleanup(srun_handle context);

#ifdef __cplusplus
}
#endif

#endif
