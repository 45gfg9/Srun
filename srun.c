/* Copyright © 2023-2024 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "srun.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#ifndef ESP_PLATFORM
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define srun_digest_update(hashctx, data, len) EVP_DigestUpdate((hashctx), (data), (len))

#define srun_log_e(handle, fmt, ...)       \
  do {                                     \
    if (handle->verbosity >= -1) {         \
      fprintf(stderr, fmt, ##__VA_ARGS__); \
      fputc('\n', stderr);                 \
    }                                      \
  } while (0)

#define srun_log_v(handle, fmt, ...)           \
  do {                                         \
    if (handle->verbosity >= 1) {              \
      fprintf(stderr, "[%s]: ", __FUNCTION__); \
      fprintf(stderr, fmt, ##__VA_ARGS__);     \
      fputc('\n', stderr);                     \
    }                                          \
  } while (0)

#else
#include <esp_log.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <cJSON.h>
#include <mbedtls/md.h>
#include <esp_log.h>

#define SRUN_LOG_TAG "srun"

#define srun_digest_update(hashctx, data, len) mbedtls_md_update(&(hashctx), (const uint8_t *)(data), (len))

// these macros are used for debugging only
// you should NOT define ESP_LOG_LEVEL in this source
// unless you are trying to contribute to the project!
#define srun_log_e(ctx, fmt, ...) ESP_LOGE(SRUN_LOG_TAG, fmt, ##__VA_ARGS__)
#define srun_log_v(ctx, fmt, ...) ESP_LOGV(SRUN_LOG_TAG, fmt, ##__VA_ARGS__)

#endif

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"

#define CHALL_N "200"
#define CHALL_TYPE "1"

struct srun_context {
  char *username;
  char *password;
  char *client_ip;
  char *auth_server;
  const char *server_cert;

  int verbosity;
  int esp_use_crt_bundle;
};

static inline uint8_t checked_subscript(const uint8_t *arr, size_t arr_len, size_t idx) {
  return idx < arr_len ? arr[idx] : 0;
}

#ifndef ESP_PLATFORM
static int curl_req_err(srun_handle handle, CURLcode code) {
  switch (code) {
    case CURLE_OK:
      return 0;
    case CURLE_COULDNT_RESOLVE_HOST:
      srun_log_e(handle, "Could not resolve host %s. Are you connected to the right network?", handle->auth_server);
      // fallthrough
    default:
      srun_log_e(handle, "libcurl returned error %d: %s", code, curl_easy_strerror(code));
      return 1;
  }
}

static size_t curl_null_write_cb(const void *ptr, size_t size, size_t nmemb, void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}
#endif

#ifdef ESP_PLATFORM
static esp_err_t _ac_id_http_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_HEADER) {
    const char *ac_id = strstr(evt->header_value, "ac_id=");
    if (strcasecmp(evt->header_key, "Location") == 0 && ac_id != NULL) {
      *((int *)evt->user_data) = atoi(ac_id + 6);
    }
  }
  return ESP_OK;
}
#endif

static int get_ac_id(srun_handle handle, int *ac_id) {
#ifdef ESP_PLATFORM
  *ac_id = -1;

  esp_http_client_config_t *config = calloc(1, sizeof(esp_http_client_config_t));

  config->url = handle->auth_server;
  config->method = HTTP_METHOD_GET;
  config->cert_pem = handle->server_cert;
  config->event_handler = _ac_id_http_handler;
  config->user_data = ac_id;
  if (handle->esp_use_crt_bundle == 1) {
    config->crt_bundle_attach = esp_crt_bundle_attach;
  }

  esp_http_client_handle_t client = esp_http_client_init(config);
  free(config);
  config = NULL;

  int status_code;
  do {
    if (esp_http_client_open(client, 0) != ESP_OK) {
      srun_log_e(handle, "Failed to open connection");
      break;
    }
    esp_http_client_fetch_headers(client);
    status_code = esp_http_client_get_status_code(client);
    esp_http_client_set_redirection(client);
    esp_http_client_close(client);
    srun_log_v(handle, "status code: %d", status_code);
  } while (status_code != 200 && *ac_id == -1);

  esp_http_client_cleanup(client);

  if (*ac_id == -1) {
    return SRUNE_NETWORK;
  }
  return SRUNE_OK;
#else
  CURL *curl_handle = curl_easy_init();

  // assume 1024 bytes is enough for the URL
  char url_buf[1024];
  strcpy(url_buf, handle->auth_server);

  int retval = 0;

  while (1) {
    curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_null_write_cb);

    CURLcode res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
      srun_log_e(handle, "Failed to fetch URL: %s", curl_easy_strerror(res));
      retval = res;
      break;
    }

    char *new_url;
    curl_easy_getinfo(curl_handle, CURLINFO_REDIRECT_URL, &new_url);
    if (!new_url) {
      srun_log_e(handle, "No redirect URL found");
      retval = CURLE_HTTP_RETURNED_ERROR;
      break;
    } else if (strcmp(new_url, url_buf) == 0) {
      srun_log_e(handle, "Redirect loop detected");
      retval = CURLE_HTTP_RETURNED_ERROR;
      break;
    } else {
      const char *ac_id_str = strstr(new_url, "ac_id=");
      if (ac_id_str) {
        *ac_id = atoi(ac_id_str + 6);
        break;
      } else {
        strcpy(url_buf, new_url);
      }
    }
  }

  curl_easy_cleanup(curl_handle);
  return retval;
#endif
}

static size_t s_encode(const uint8_t *msg, size_t msg_len, uint32_t *dst, int append_len) {
  size_t i;
  for (i = 0; i < msg_len; i += 4) {
    dst[i / 4] = (checked_subscript(msg, msg_len, i + 3) << 24) | (checked_subscript(msg, msg_len, i + 2) << 16)
                 | (checked_subscript(msg, msg_len, i + 1) << 8) | checked_subscript(msg, msg_len, i);
  }
  if (append_len) {
    dst[i / 4] = msg_len;
  }
  return msg_len / 4 + (msg_len % 4 != 0) + append_len;
}

// named `l_encode` in the original javascript code
static size_t s_decode(const uint32_t *msg, size_t msg_len, uint8_t *dst, size_t dst_len) {
  size_t retlen = msg_len * 4;

  if (retlen > dst_len) {
    return 0;
  }

  for (size_t i = 0; i < retlen; i++) {
    dst[i] = msg[i / 4] >> (i % 4 * 8);
  }

  return retlen;
}

static size_t x_encode(const uint8_t *src, size_t src_len, const uint8_t key[static 16], uint8_t *dst, size_t dst_len) {
  if (src_len == 0) {
    return 0;
  }

  uint32_t n = src_len / 4 + (src_len % 4 != 0) + 1;
  uint32_t *encoded_msg = (uint32_t *)calloc(n, sizeof(uint32_t));
  uint32_t *encoded_key = (uint32_t *)calloc(4, sizeof(uint32_t));

  s_encode(src, src_len, encoded_msg, 1);
  s_encode(key, 16, encoded_key, 0);

  for (uint32_t d = 0, z = encoded_msg[n - 1], q = 6 + 52 / n; q; q--) {
    d += 0x9e3779b9;
    for (uint32_t p = 0; p < n; p++) {
      uint32_t y = encoded_msg[(p + 1) % n];
      encoded_msg[p] += (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (encoded_key[(p & 3) ^ (d >> 2 & 3)] ^ z);
      z = encoded_msg[p];
    }
  }

  size_t retlen = s_decode(encoded_msg, n, dst, dst_len);

  free(encoded_key);
  free(encoded_msg);

  return retlen;
}

static size_t b64_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
  // the result string length, including the trailing '\0'
  size_t retlen = (src_len + 2) / 3 * 4 + 1;

  if (dst_len < retlen) {
    return 0;
  }

  for (size_t i = 0; i < src_len; i += 3) {
    uint32_t n = (checked_subscript(src, src_len, i) << 16) | (checked_subscript(src, src_len, i + 1) << 8)
                 | checked_subscript(src, src_len, i + 2);
    for (size_t j = 0; j < 4; j++) {
      dst[i / 3 * 4 + j] =
          "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"[(n >> (18 - j * 6)) & 0x3f];
    }
  }
  for (int i = 0; i < (src_len % 3 != 0) + (src_len % 3 == 1); i++) {
    dst[retlen - 2 - i] = '=';
  }
  dst[retlen - 1] = '\0';

  return retlen;
}

// url encode, adjust the size of *str accordingly
static size_t url_encode(char **str) {
  // get destination size
  size_t new_dest_len = strlen(*str);
  for (char *src_ptr = *str; *src_ptr; ++src_ptr) {
    if (!(isalnum((int)*src_ptr) || strchr("-._~", *src_ptr)))
      new_dest_len += 2;
  }

  // do actual format
  size_t dest_pos = 0;
  char *new_str = malloc(new_dest_len + 1);
  for (char *src_ptr = *str; *src_ptr; ++src_ptr) {
    if (isalnum((int)*src_ptr) || strchr("-._~", *src_ptr)) {
      new_str[dest_pos++] = *src_ptr;
    } else {
      dest_pos += snprintf(new_str + dest_pos, new_dest_len + 1 - dest_pos, "%%%02hhX", (uint8_t)*src_ptr);
    }
  }
  new_str[new_dest_len] = 0;
  free(*str);
  *str = new_str;
  return new_dest_len;
}

static char *srun_strdup(const char *str) {
  char *ret = malloc(strlen(str) + 1);
  if (ret) {
    strcpy(ret, str);
  }
  return ret;
}

srun_handle srun_create() {
  // allocate a new context
  srun_handle handle = calloc(1, sizeof(struct srun_context));
  srun_setopt(handle, SRUNOPT_CLIENT_IP, "0.0.0.0");
  return handle;
}

void srun_cleanup(srun_handle handle) {
  if (handle->password) {
    memset(handle->password, 0, strlen(handle->password));
  }
  free(handle->username);
  free(handle->password);
  free(handle->client_ip);
  free(handle->auth_server);
  free(handle);
}

void srun_setopt(srun_handle handle, srun_option option, ...) {
  va_list args;
  va_start(args, option);

  const char *src_str;

  // TODO: more robust realloc handling
  switch (option) {
    case SRUNOPT_AUTH_SERVER:
      src_str = va_arg(args, char *);
      handle->auth_server = realloc(handle->auth_server, strlen(src_str) + 1);
      strcpy(handle->auth_server, src_str);
      break;
    case SRUNOPT_USERNAME:
      src_str = va_arg(args, char *);
      handle->username = realloc(handle->username, strlen(src_str) + 1);
      strcpy(handle->username, src_str);
      break;
    case SRUNOPT_PASSWORD:
      src_str = va_arg(args, char *);
      handle->password = realloc(handle->password, strlen(src_str) + 1);
      strcpy(handle->password, src_str);
      break;
    case SRUNOPT_SERVER_CERT:
      handle->server_cert = va_arg(args, const char *);
      break;
    case SRUNOPT_USE_ESP_CRT_BUNDLE:
      handle->esp_use_crt_bundle = va_arg(args, int);
      break;
    case SRUNOPT_CLIENT_IP:
      src_str = va_arg(args, char *);
      handle->client_ip = realloc(handle->client_ip, strlen(src_str) + 1);
      strcpy(handle->client_ip, src_str);
      break;
    case SRUNOPT_VERBOSITY:
      handle->verbosity = va_arg(args, int);
      break;
  }

  va_end(args);
}

int srun_login(srun_handle handle) {
  // first, retrieve challenge string
  // construct target url

  if (!(handle->auth_server && handle->username && handle->password)) {
    return SRUNE_INVALID_CTX;
  }

  int ac_id;
  if (get_ac_id(handle, &ac_id) != 0) {
    srun_log_e(handle, "Failed to get ac_id");
    return SRUNE_NETWORK;
  }
  srun_log_v(handle, "acquired ac_id: %d", ac_id);

  unsigned long ctx_time = (unsigned long)time(NULL);
  int randnum = rand();

  const char *const CHAL_FMTSTR = "%s" PATH_GET_CHAL "?username=%s"
                                  "&ip=%s"
                                  "&callback=jQuery_%d_%lu000"
                                  "&_=%lu000";

  char *url_buf = NULL;
  asprintf(&url_buf, CHAL_FMTSTR, handle->auth_server, handle->username, handle->client_ip, randnum, ctx_time,
           ctx_time);

  srun_log_v(handle, "chall url: %s", url_buf);

#ifndef ESP_PLATFORM
  CURL *curl_handle = curl_easy_init();
  FILE *tmp_file = tmpfile();
  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, tmp_file);
  if (handle->verbosity >= 2) {
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  }

  if (handle->server_cert) {
    struct curl_blob cert_blob = {
        .data = (void *)handle->server_cert,
        .len = strlen(handle->server_cert),
        .flags = CURL_BLOB_NOCOPY,
    };
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO_BLOB, &cert_blob);
  }

  free(url_buf);
  url_buf = NULL;
  if (curl_req_err(handle, curl_easy_perform(curl_handle))) {
    fclose(tmp_file);
    curl_easy_cleanup(curl_handle);
    return SRUNE_NETWORK;
  }

  size_t buf_size = ftell(tmp_file);
  rewind(tmp_file);
  char *char_buf = malloc(buf_size + 1);
  fread(char_buf, buf_size, 1, tmp_file);
#else
  esp_http_client_config_t *config = calloc(1, sizeof(esp_http_client_config_t));
  config->url = url_buf;
  config->method = HTTP_METHOD_GET;
  config->cert_pem = handle->server_cert;
  config->buffer_size_tx = 768;
  if (handle->esp_use_crt_bundle == 1) {
    config->crt_bundle_attach = esp_crt_bundle_attach;
  }
  esp_http_client_handle_t client = esp_http_client_init(config);
  free(config);
  config = NULL;

  if (esp_http_client_open(client, 0) != ESP_OK) {
    srun_log_e(handle, "failed to open connection");
    esp_http_client_cleanup(client);
    free(url_buf);
    return SRUNE_NETWORK;
  }

  // Content-Length
  size_t buf_size = esp_http_client_fetch_headers(client);
  int status_code = esp_http_client_get_status_code(client);
  if (status_code != 200) {
    srun_log_e(handle, "server responsed status code %d", status_code);
    esp_http_client_cleanup(client);
    free(url_buf);
    return SRUNE_NETWORK;
  }
  char *char_buf = malloc(buf_size + 1);
  esp_http_client_read_response(client, char_buf, buf_size);
  esp_http_client_close(client);

  free(url_buf);
  url_buf = NULL;
#endif
  char_buf[buf_size] = 0;
  srun_log_v(handle, "server response: %s", char_buf);

  // locate the beginning of json
  cJSON *json = cJSON_Parse(strchr(char_buf, '{'));
  free(char_buf);
  char_buf = NULL;

  ctx_time = cJSON_GetObjectItem(json, "st")->valueint;

  srun_setopt(handle, SRUNOPT_CLIENT_IP, cJSON_GetObjectItem(json, "online_ip")->valuestring);

  char *chall = srun_strdup(cJSON_GetObjectItem(json, "challenge")->valuestring);
  const size_t chall_length = strlen(chall);
  srun_log_v(handle, "chall = %s", chall);

  cJSON_Delete(json);
  json = NULL;

  if (chall_length < 16) {
    fputs("FATAL: server challenge too short", stderr);
    abort();
  }

  asprintf(&char_buf, "%d", ac_id);

  char md5_buf[33];
  unsigned int md_len = sizeof md5_buf / 2;

#ifndef ESP_PLATFORM
  HMAC(EVP_md5(), chall, (int)chall_length, (const uint8_t *)handle->password, strlen(handle->password),
       (uint8_t *)md5_buf + md_len, &md_len);
#else
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), (const uint8_t *)handle->password,
                  strlen(handle->password), (const uint8_t *)chall, chall_length, (uint8_t *)md5_buf + md_len);
#endif
  for (unsigned int i = 0; i < md_len; i++) {
    snprintf(md5_buf + 2 * i, 3, "%02hhx", (uint8_t)md5_buf[md_len + i]);
  }

#ifndef ESP_PLATFORM
  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  EVP_MD_CTX_reset(hashctx);
  EVP_DigestInit(hashctx, EVP_sha1());
#else
  mbedtls_md_context_t hashctx;
  mbedtls_md_init(&hashctx);
  mbedtls_md_setup(&hashctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
  mbedtls_md_starts(&hashctx);
#endif
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, handle->username, strlen(handle->username));
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, md5_buf, 32);
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, char_buf, strlen(char_buf)); // ac_id
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, handle->client_ip, strlen(handle->client_ip));
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, CHALL_N, strlen(CHALL_N)); // n
  srun_digest_update(hashctx, chall, chall_length);
  srun_digest_update(hashctx, CHALL_TYPE, strlen(CHALL_TYPE)); // type
  srun_digest_update(hashctx, chall, chall_length);

  srun_log_v(handle, "md5 = %s", md5_buf);
  srun_log_v(handle, "hash update: %s%s", chall, handle->username);
  srun_log_v(handle, "hash update: %s%s", chall, md5_buf);
  srun_log_v(handle, "hash update: %s%s", chall, char_buf);
  srun_log_v(handle, "hash update: %s%s", chall, handle->client_ip);
  srun_log_v(handle, "hash update: %s%s", chall, CHALL_N);
  srun_log_v(handle, "hash update: %s%s", chall, CHALL_TYPE);

  // calculate challenge response
  // format info string
  json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "username", handle->username);
  cJSON_AddStringToObject(json, "password", handle->password);
  cJSON_AddStringToObject(json, "ip", handle->client_ip);
  cJSON_AddStringToObject(json, "acid", char_buf);
  cJSON_AddStringToObject(json, "enc_ver", "srun_bx1");

  char *formatted = cJSON_PrintUnformatted(json);
  buf_size = strlen(formatted);
  size_t info_len = (buf_size / 4 + (buf_size % 4 != 0) + 1) * 4;
  free(char_buf);
  char_buf = malloc(info_len); // x-encoded payload
  x_encode((const uint8_t *)formatted, buf_size, (const uint8_t *)chall, (uint8_t *)char_buf, info_len);

  cJSON_free(formatted);
  formatted = NULL;
  cJSON_Delete(json);
  json = NULL;

  buf_size = 7 + (info_len + 2) / 3 * 4;
  formatted = malloc(buf_size + 1);
  strncpy(formatted, "{SRBX1}", buf_size);
  b64_encode((const uint8_t *)char_buf, info_len, formatted + 7, buf_size - 6);

  srun_digest_update(hashctx, formatted, buf_size); // http info param

  srun_log_v(handle, "hash update: %s%s", chall, formatted);

  url_encode(&formatted);

  free(char_buf);
  char_buf = NULL;
  free(chall);
  chall = NULL;

  char sha1_buf[41];
  md_len = sizeof sha1_buf / 2;
#ifndef ESP_PLATFORM
  EVP_DigestFinal(hashctx, (uint8_t *)sha1_buf + md_len, &md_len);
  EVP_MD_CTX_free(hashctx);
  hashctx = NULL;
#else
  mbedtls_md_finish(&hashctx, (uint8_t *)sha1_buf + md_len);
  mbedtls_md_free(&hashctx);
#endif
  for (unsigned int i = 0; i < md_len; i++) {
    snprintf(sha1_buf + 2 * i, 3, "%02hhx", (uint8_t)sha1_buf[md_len + i]);
  }
  srun_log_v(handle, "sha1 = %s", sha1_buf);

  const char *const PORTAL_FMTSTR = "%s" PATH_PORTAL "?callback=jQuery%d_%lu000"
                                    "&_=%lu000"
                                    "&username=%s"
                                    "&password=%%7BMD5%%7D%s"
                                    "&ac_id=%d"
                                    "&ip=%s"
                                    "&chksum=%s"
                                    "&info=%s"
                                    "&action=login"
                                    "&n=200"
                                    "&type=1"
                                    "&os=Linux"
                                    "&name=Linux"
                                    "&double_stack=0";

  asprintf(&url_buf, PORTAL_FMTSTR, handle->auth_server, randnum, ctx_time, ctx_time, handle->username, md5_buf, ac_id,
           handle->client_ip, sha1_buf, formatted);

  free(formatted);
  formatted = NULL;

  srun_log_v(handle, "portal url: %s", url_buf);
#ifndef ESP_PLATFORM
  rewind(tmp_file);
  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  CURLcode curl_res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  free(url_buf);

  if (curl_req_err(handle, curl_res)) {
    fclose(tmp_file);

    return SRUNE_NETWORK;
  }

  buf_size = ftell(tmp_file);
  rewind(tmp_file);
  char_buf = malloc(buf_size + 1);
  fread(char_buf, buf_size, 1, tmp_file);
  fclose(tmp_file);
#else
  esp_http_client_set_url(client, url_buf);
  free(url_buf);
  url_buf = NULL;

  if (esp_http_client_open(client, 0) != ESP_OK) {
    srun_log_e(handle, "failed to open connection");
    esp_http_client_cleanup(client);
    return SRUNE_NETWORK;
  }

  // Content-Length
  buf_size = esp_http_client_fetch_headers(client);
  status_code = esp_http_client_get_status_code(client);
  if (status_code != 200) {
    srun_log_e(handle, "server responsed status code %d", status_code);
    esp_http_client_cleanup(client);
    return SRUNE_NETWORK;
  }
  char_buf = malloc(buf_size + 1);
  esp_http_client_read_response(client, char_buf, buf_size);
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
#endif

  char_buf[buf_size] = 0;

  srun_log_v(handle, "server response: %s", char_buf);

  json = cJSON_Parse(strchr(char_buf, '{'));
  free(char_buf);
  char_buf = NULL;

  int ret = SRUNE_OK;
  const char *errmsg = cJSON_GetObjectItem(json, "error_msg")->valuestring;
  if (strlen(errmsg) != 0) {
    cJSON *ecode = cJSON_GetObjectItem(json, "ecode");
    if (cJSON_IsNumber(ecode)) {
      ret = ecode->valueint;
    } else if (cJSON_IsString(ecode)) {
      srun_log_e(handle, "Gateway error code: %s", ecode->valuestring);
      srun_log_e(handle, "Message: %s", errmsg);
      ret = (int)strtol(ecode->valuestring + 1, NULL, 10);
    }
  }

  cJSON_Delete(json);
  return ret;
}

int srun_logout(srun_handle handle) {
  if (!handle->auth_server) {
    return SRUNE_INVALID_CTX;
  }

  const char *const LOGOUT_FMTSTR = "%s" PATH_PORTAL "?action=logout";

  char *url_buf = NULL;
#ifndef ESP_PLATFORM
  CURL *curl_handle = curl_easy_init();
  asprintf(&url_buf, LOGOUT_FMTSTR, handle->auth_server);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_null_write_cb);
  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  if (handle->verbosity >= 2) {
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  }

  CURLcode curl_res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  free(url_buf);

  if (curl_req_err(handle, curl_res)) {
    return SRUNE_NETWORK;
  }
#else
  asprintf(&url_buf, LOGOUT_FMTSTR, handle->auth_server);

  esp_http_client_config_t *config = calloc(1, sizeof(esp_http_client_config_t));
  config->url = url_buf;
  config->method = HTTP_METHOD_GET;
  config->cert_pem = handle->server_cert;
  esp_http_client_handle_t client = esp_http_client_init(config);
  esp_err_t err = esp_http_client_perform(client);
  esp_http_client_cleanup(client);
  free(config);
  free(url_buf);
  if (err != ESP_OK) {
    srun_log_e(handle, "failed to open connection");

    return SRUNE_NETWORK;
  }
#endif

  return SRUNE_OK;
}
