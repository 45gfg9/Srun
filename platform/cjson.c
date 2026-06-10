/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if ESP_PLATFORM || ESP32
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif

int parse_chall_response(struct chall_response *response, const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    errno = EINVAL; // Invalid JSON format
    return -1;
  }

  cJSON *challenge = cJSON_GetObjectItem(root, "challenge");
  cJSON *client_ip = cJSON_GetObjectItem(root, "client_ip");

  if (!cJSON_IsString(challenge) || !cJSON_IsString(client_ip)) {
    cJSON_Delete(root);
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct chall_response r;
  r.token = strdup(challenge->valuestring);
  r.client_ip = strdup(client_ip->valuestring);

  cJSON_Delete(root);

  if (!r.token || !r.client_ip) {
    free_chall_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

int parse_portal_response(struct portal_response *response, const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    errno = EINVAL; // Invalid JSON format
    return -1;
  }

  cJSON *ecode = cJSON_GetObjectItem(root, "ecode");
  cJSON *error = cJSON_GetObjectItem(root, "error");
  cJSON *error_msg = cJSON_GetObjectItem(root, "error_msg");

  if (!(cJSON_IsString(ecode) || cJSON_IsNumber(ecode)) || !cJSON_IsString(error) || !cJSON_IsString(error_msg)) {
    cJSON_Delete(root);
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct portal_response r;
  if (cJSON_IsString(ecode)) {
    r.ecode = strdup(ecode->valuestring);
  } else if (asprintf(&r.ecode, "%d", ecode->valueint) == -1) {
    // some error occurred
    r.ecode = NULL;
  }
  r.error = strdup(error->valuestring);
  r.error_msg = strdup(error_msg->valuestring);

  cJSON_Delete(root);

  if (!r.error || !r.error_msg || !r.ecode) {
    free_portal_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

char *create_info_field(const_srun_handle handle, const char *enc_ver) {
  cJSON *info = cJSON_CreateObject();
  if (!info) {
    errno = ENOMEM;
    return NULL;
  }

  cJSON_AddStringToObject(info, "username", handle->username);
  cJSON_AddStringToObject(info, "password", handle->password);
  cJSON_AddStringToObject(info, "ip", handle->ip);
  cJSON_AddNumberToObject(info, "acid", handle->ac_id);
  cJSON_AddStringToObject(info, "enc_ver", enc_ver);

  char *info_str = cJSON_PrintUnformatted(info);
  cJSON_Delete(info);

  if (!info_str) {
    errno = ENOMEM;
    return NULL;
  }

  char *ret = strdup(info_str);
  cJSON_free(info_str);
  return ret;
}
