/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <ArduinoJson.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int parse_chall_response(struct chall_response *response, const char *json) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(512);
#endif

  DeserializationError error = deserializeJson(doc, json);
  if (error) {
    if (error.code() == DeserializationError::NoMemory) {
      errno = ENOMEM;
    } else {
      errno = EINVAL;
    }
    return -1;
  }

  const char *challenge = doc["challenge"];
  const char *client_ip = doc["client_ip"];

  if (!challenge || !client_ip) {
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct chall_response r;
  r.token = strdup(challenge);
  r.client_ip = strdup(client_ip);

  if (!r.token || !r.client_ip) {
    free_chall_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

int parse_portal_response(struct portal_response *response, const char *json) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(512);
#endif

  DeserializationError error = deserializeJson(doc, json);
  if (error) {
    if (error.code() == DeserializationError::NoMemory) {
      errno = ENOMEM;
    } else {
      errno = EINVAL;
    }
    return -1;
  }

  JsonVariant ecode = doc["ecode"];
  const char *error_msg = doc["error_msg"];
  const char *error_str = doc["error"];

  if (!(ecode.is<int>() || ecode.is<const char *>()) || !error_msg || !error_str) {
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct portal_response r;
  if (ecode.is<const char *>()) {
    r.ecode = strdup(ecode.as<const char *>());
  } else if (asprintf(&r.ecode, "%d", ecode.as<int>()) == -1) {
    // some error occurred
    r.ecode = NULL;
  }
  r.error = strdup(error_str);
  r.error_msg = strdup(error_msg);

  if (!r.ecode || !r.error || !r.error_msg) {
    free_portal_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

char *create_info_field(const_srun_handle handle, const char *enc_ver) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(384);
#endif
  doc["username"] = handle->username;
  doc["password"] = handle->password;
  doc["ip"] = handle->ip;
  doc["acid"] = handle->ac_id;
  doc["enc_ver"] = enc_ver;

  size_t capacity = measureJson(doc) + 1;
  char *info_str = (char *)malloc(capacity);
  if (info_str) {
    serializeJson(doc, info_str, capacity);
  }
  return info_str;
}
