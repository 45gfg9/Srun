#include "srun.h"
#include <string.h>
#include <cjson/cJSON.h>
#include <ctype.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"

#define srun_log_v(ctx, fmt, ...)                                                    \
  do {                                                                               \
    if (ctx->verbose) {                                                              \
      fprintf(stderr, "[%s]: ", __FUNCTION__) + fprintf(stderr, fmt, ##__VA_ARGS__); \
    }                                                                                \
  } while (0)

static inline uint8_t checked_subscript(const uint8_t *arr, size_t arr_len, size_t idx) {
  return idx < arr_len ? arr[idx] : 0;
}

static inline size_t x_max(size_t a, size_t b) {
  return a > b ? a : b;
}

static int curl_req_err(srun_context *ctx, CURLcode code) {
  switch (code) {
    case CURLE_OK:
      return 0;
    case CURLE_COULDNT_RESOLVE_HOST:
      srun_log_v(ctx, "Could not resolve host %s. Are you connected to the right network?\n", ctx->auth_server);
    default:
      srun_log_v(ctx, "libcurl returned error %d: %s", code, curl_easy_strerror(code));
      return 1;
  }
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

static size_t x_encode(const uint8_t *src, size_t src_len, const uint8_t *key, size_t key_len, uint8_t *dst,
                       size_t dst_len) {
  if (src_len == 0) {
    return 0;
  }

  uint32_t *encoded_msg = (uint32_t *)calloc(src_len / 4 + (src_len % 4 != 0) + 1, sizeof(uint32_t));
  uint32_t *encoded_key = (uint32_t *)calloc(x_max(4, key_len / 4 + (key_len % 4 != 0)), sizeof(uint32_t));

  size_t encoded_msg_len = s_encode(src, src_len, encoded_msg, 1);
  s_encode(key, key_len, encoded_key, 0);

  uint32_t n = src_len / 4 + (src_len % 4 != 0);
  uint32_t z = encoded_msg[n];
  uint32_t d = 0;

  for (uint32_t q = 6 + 52 / (n + 1); q; q--) {
    d += 0x9e3779b9;
    uint32_t e = d >> 2 & 3;
    for (uint32_t p = 0; p < n; p++) {
      uint32_t y = encoded_msg[p + 1];
      uint32_t m = z >> 5 ^ y << 2;
      m += ((y >> 3 ^ z << 4) ^ (d ^ y));
      m += (encoded_key[(p & 3) ^ e] ^ z);
      encoded_msg[p] += m;
      z = encoded_msg[p];
    }
    uint32_t y = encoded_msg[0];
    uint32_t m = z >> 5 ^ y << 2;
    m += ((y >> 3 ^ z << 4) ^ (d ^ y));
    m += (encoded_key[(n & 3) ^ e] ^ z);
    encoded_msg[n] += m;
    z = encoded_msg[n];
  }

  size_t retlen = s_decode(encoded_msg, encoded_msg_len, dst, dst_len);

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
  for (size_t i = 0; i < (src_len % 3 != 0) + (src_len % 3 == 1); i++) {
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
    if (!(isalnum(*src_ptr) || strchr("-._~", *src_ptr)))
      new_dest_len += 2;
  }

  // format
  size_t dest_pos = 0;
  char *new_str = malloc(new_dest_len + 1);
  for (char *src_ptr = *str; *src_ptr; ++src_ptr) {
    if (isalnum(*src_ptr) || strchr("-._~", *src_ptr)) {
      new_str[dest_pos++] = *src_ptr;
    } else {
      dest_pos += snprintf(new_str + dest_pos, new_dest_len + 1 - dest_pos, "%%%02hhX", *src_ptr);
    }
  }
  new_str[new_dest_len] = 0;
  free(*str);
  *str = new_str;
  return new_dest_len;
}

void srun_init(srun_context *ctx) {
  // set all fields to null
  memset(ctx, 0, sizeof *ctx);
  srun_setopt(ctx, SRUNOPT_CLIENT_IP, "0.0.0.0");
  ctx->randnum = rand();
}

void srun_cleanup(srun_context *ctx) {
  free(ctx->username);
  free(ctx->password);
  free(ctx->client_ip);
  free(ctx->auth_server);
  memset(ctx, 0, sizeof *ctx);
}

void srun_setopt(srun_context *ctx, srun_option option, ...) {
  va_list args;
  va_start(args, option);

  const char *src_str;

  switch (option) {
    case SRUNOPT_USERNAME:
      src_str = va_arg(args, char *);
      ctx->username = realloc(ctx->username, strlen(src_str) + 1);
      strcpy(ctx->username, src_str);
      break;
    case SRUNOPT_PASSWORD:
      src_str = va_arg(args, char *);
      ctx->password = realloc(ctx->password, strlen(src_str) + 1);
      strcpy(ctx->password, src_str);
      break;
    case SRUNOPT_CLIENT_IP:
      src_str = va_arg(args, char *);
      ctx->client_ip = realloc(ctx->client_ip, strlen(src_str) + 1);
      strcpy(ctx->client_ip, src_str);
      break;
    case SRUNOPT_AUTH_SERVER:
      src_str = va_arg(args, char *);
      ctx->auth_server = realloc(ctx->auth_server, strlen(src_str) + 1);
      strcpy(ctx->auth_server, src_str);
      break;
    case SRUNOPT_AC_ID:
      ctx->ac_id = va_arg(args, int);
      break;
    case SRUNOPT_VERBOSE:
      ctx->verbose = va_arg(args, int);
      break;
  }

  va_end(args);
}

int srun_login(srun_context *ctx) {
  // first, retrieve challenge string
  // construct target url

  if (!(ctx->auth_server && ctx->username && ctx->password)) {
    return SRUNE_INVALID_CTX;
  }

  time(&ctx->ctx_time);

  const char *const CHAL_FMTSTR = "%s" PATH_GET_CHAL "?username=%s"
                                  "&ip=%s"
                                  "&callback=jQuery_%d_%ld000"
                                  "&_=%ld000";

  size_t url_len = snprintf(NULL, 0, CHAL_FMTSTR, ctx->auth_server, ctx->username, ctx->client_ip, ctx->randnum,
                            ctx->ctx_time, ctx->ctx_time);

  char *url_buf = malloc(url_len + 1);
  snprintf(url_buf, url_len + 1, CHAL_FMTSTR, ctx->auth_server, ctx->username, ctx->client_ip, ctx->randnum,
           ctx->ctx_time, ctx->ctx_time);

  CURL *curl_handle = curl_easy_init();
  FILE *tmp_file = tmpfile();
  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, tmp_file);

  free(url_buf);
  CURLcode curl_res = curl_easy_perform(curl_handle);
  if (curl_req_err(ctx, curl_res)) {
    fclose(tmp_file);
    curl_easy_cleanup(curl_handle);
    return SRUNE_NETWORK;
  }

  size_t buf_size = ftell(tmp_file);
  rewind(tmp_file);
  char *char_buf = malloc(buf_size + 1);
  fread(char_buf, buf_size, 1, tmp_file);
  char_buf[buf_size] = 0;
  srun_log_v(ctx, "server json = %s\n", char_buf);

  // locate the beginning of json
  cJSON *json = cJSON_Parse(strchr(char_buf, '{'));
  free(char_buf);
  char_buf = NULL;

  ctx->ctx_time = cJSON_GetObjectItem(json, "st")->valueint;

  srun_setopt(ctx, SRUNOPT_CLIENT_IP, cJSON_GetObjectItem(json, "online_ip")->valuestring);

  char *chall = strdup(cJSON_GetObjectItem(json, "challenge")->valuestring);
  const size_t chall_length = strlen(chall);
  srun_log_v(ctx, "chall = %s\n", chall);

  cJSON_Delete(json);
  json = NULL;

  buf_size = snprintf(NULL, 0, "%d", ctx->ac_id);
  char_buf = malloc(buf_size + 1);
  snprintf(char_buf, buf_size + 1, "%d", ctx->ac_id);

  // calculate challenge response
  // format info string
  json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "username", ctx->username);
  cJSON_AddStringToObject(json, "password", ctx->password);
  cJSON_AddStringToObject(json, "ip", ctx->client_ip);
  cJSON_AddStringToObject(json, "acid", char_buf);
  cJSON_AddStringToObject(json, "enc_ver", "srun_bx1");

  char md5_buf[33];
  unsigned int md_len = sizeof md5_buf / 2;

  HMAC(EVP_md5(), chall, (int)chall_length, (const uint8_t *)ctx->password, strlen(ctx->password),
       (uint8_t *)md5_buf + md_len, &md_len);
  memset(ctx->password, 0, strlen(ctx->password));
  free(ctx->password);
  ctx->password = NULL;
  for (int i = 0; i < md_len; i++) {
    snprintf(md5_buf + 2 * i, 3, "%02hhx", md5_buf[md_len + i]);
  }

  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  EVP_MD_CTX_reset(hashctx);
  EVP_DigestInit(hashctx, EVP_sha1());
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, ctx->username, strlen(ctx->username));
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, md5_buf, 32);
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, char_buf, strlen(char_buf)); // ac_id
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, ctx->client_ip, strlen(ctx->client_ip));
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, "200", 3); // n
  EVP_DigestUpdate(hashctx, chall, chall_length);
  EVP_DigestUpdate(hashctx, "1", 1); // type
  EVP_DigestUpdate(hashctx, chall, chall_length);

  srun_log_v(ctx, "md5 = %s\n", md5_buf);
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, ctx->username);
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, md5_buf);
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, char_buf);
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, ctx->client_ip);
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, "200");
  srun_log_v(ctx, "hash update: %*s%s\n", (int)chall_length, chall, "1");

  char *formatted = cJSON_PrintUnformatted(json);
  buf_size = strlen(formatted);
  size_t info_len = (buf_size / 4 + (buf_size % 4 != 0) + 1) * 4;
  free(char_buf);
  char_buf = malloc(info_len);
  x_encode((const uint8_t *)formatted, buf_size, (const uint8_t *)chall, chall_length, (uint8_t *)char_buf, info_len);

  cJSON_free(formatted);
  formatted = NULL;
  cJSON_Delete(json);
  json = NULL;

  buf_size = 7 + (info_len + 2) / 3 * 4;
  formatted = malloc(buf_size + 1);
  strncpy(formatted, "{SRBX1}", buf_size);
  b64_encode((const uint8_t *)char_buf, info_len, formatted + 7, buf_size - 6);

  EVP_DigestUpdate(hashctx, formatted, buf_size); // info

  srun_log_v(ctx, "hash update: %*s%*s\n", (int)chall_length, chall, (int)buf_size, formatted);

  free(char_buf);
  char_buf = NULL;
  free(chall);
  chall = NULL;

  char sha1_buf[41];
  md_len = sizeof sha1_buf / 2;
  EVP_DigestFinal(hashctx, (uint8_t *)sha1_buf + md_len, &md_len);
  EVP_MD_CTX_free(hashctx);
  hashctx = NULL;
  for (int i = 0; i < md_len; i++) {
    snprintf(sha1_buf + 2 * i, 3, "%02hhx", sha1_buf[md_len + i]);
  }

  srun_log_v(ctx, "sha1 = %s\n", sha1_buf);

  url_encode(&formatted);

  const char *const PORTAL_FMTSTR = "%s" PATH_PORTAL "?callback=jQuery%d_%ld000"
                                    "&_=%ld000"
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
  // srun_log_v(ctx,"%s\n", formatted);
  strlen(formatted);

  url_len = snprintf(NULL, 0, PORTAL_FMTSTR, ctx->auth_server, ctx->randnum, ctx->ctx_time, ctx->ctx_time,
                     ctx->username, md5_buf, ctx->ac_id, ctx->client_ip, sha1_buf, formatted);
  url_buf = malloc(url_len + 1);
  snprintf(url_buf, url_len + 1, PORTAL_FMTSTR, ctx->auth_server, ctx->randnum, ctx->ctx_time, ctx->ctx_time,
           ctx->username, md5_buf, ctx->ac_id, ctx->client_ip, sha1_buf, formatted);

  free(formatted);
  formatted = NULL;

  srun_log_v(ctx, "full URL: %s\n", url_buf);

  rewind(tmp_file);
  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  curl_res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  free(url_buf);
  url_buf = NULL;

  if (curl_req_err(ctx, curl_res)) {
    fclose(tmp_file);
    return SRUNE_NETWORK;
  }

  buf_size = ftell(tmp_file);
  rewind(tmp_file);
  char_buf = malloc(buf_size + 1);
  fread(char_buf, buf_size, 1, tmp_file);
  fclose(tmp_file);
  char_buf[buf_size] = 0;

  srun_log_v(ctx, "server json: %s\n", char_buf);

  json = cJSON_Parse(strchr(char_buf, '{'));
  free(char_buf);

  int ret = SRUNE_OK;
  if (strlen(cJSON_GetObjectItem(json, "error_msg")->valuestring) != 0) {
    cJSON *ecode = cJSON_GetObjectItem(json, "ecode");
    if (cJSON_IsNumber(ecode)) {
      ret = ecode->valueint;
    } else if (cJSON_IsString(ecode)) {
      srun_log_v(ctx, "gateway error: %s\n", ecode->valuestring);
      ret = (int)strtol(ecode->valuestring + 1, NULL, 10);
    }
  }

  cJSON_Delete(json);
  return ret;
}

int srun_logout(srun_context *ctx) {
  if (!ctx->auth_server) {
    return SRUNE_INVALID_CTX;
  }

  const char *const LOGOUT_FMTSTR = "%s" PATH_PORTAL "?action=logout";

  CURL *curl_handle = curl_easy_init();
  size_t buf_size = snprintf(NULL, 0, LOGOUT_FMTSTR, ctx->auth_server);
  char *url_buf = malloc(buf_size + 1);
  snprintf(url_buf, buf_size, LOGOUT_FMTSTR, ctx->auth_server);

  curl_easy_setopt(curl_handle, CURLOPT_URL, url_buf);
  CURLcode curl_res = curl_easy_perform(curl_handle);
  free(url_buf);

  curl_easy_cleanup(curl_handle);

  if (curl_req_err(ctx, curl_res)) {
    return SRUNE_NETWORK;
  }

  return SRUNE_OK;
}
