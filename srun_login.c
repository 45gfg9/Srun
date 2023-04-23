#include "srun_login.h"
#include <string.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <ctype.h>
#include <unistd.h>

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"

#ifndef SRUN_LOGIN_AUTH_URL
#define SRUN_LOGIN_AUTH_URL NULL
#endif

#ifndef SRUN_LOGIN_AC_ID
#define SRUN_LOGIN_AC_ID 0
#endif

static CURL *curl;

static inline uint8_t checked_subscript(const uint8_t *arr, size_t arr_len, size_t idx) {
  return idx < arr_len ? arr[idx] : 0;
}

static inline size_t x_max(size_t a, size_t b) {
  return a > b ? a : b;
}

static inline void *checked_realloc(void *ptr, size_t size) {
  void *p = realloc(ptr, size);
  if (!p) {
    perror("srun_login");
    exit(1);
  }
  return p;
}

static size_t s_encode(const uint8_t *msg, size_t msg_len, uint32_t *dst, int fixlen) {
  size_t i;
  for (i = 0; i < msg_len; i += 4) {
    dst[i / 4] = (checked_subscript(msg, msg_len, i + 3) << 24) | (checked_subscript(msg, msg_len, i + 2) << 16)
                 | (checked_subscript(msg, msg_len, i + 1) << 8) | checked_subscript(msg, msg_len, i);
  }
  if (fixlen) {
    dst[i / 4] = msg_len;
  }
  return msg_len / 4 + (msg_len % 4 != 0) + fixlen;
}

static size_t s_decode(const uint32_t *msg, size_t msg_len, uint8_t *dst, size_t dst_len, int fixlen) {
  size_t retlen = fixlen ? msg[--msg_len] : msg_len * 4;

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

  // printf("encoded_msg_len(%d):", encoded_msg_len);
  // for (size_t i = 0; i < encoded_msg_len; i++) {
  //   printf(" %u", encoded_msg[i]);
  // }

  size_t retlen = s_decode(encoded_msg, encoded_msg_len, dst, dst_len, 0);

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

// TODO
static size_t curl_write_cb(char *data, size_t size, size_t nmemb, void *userp) {
  fprintf(stderr, "data = %p, size = %zu, nmemb = %zu, userp = %p\n", data, size, nmemb, userp);
  memmove(userp, data, size * nmemb);
  return size * nmemb;
}

void srun_login_init(srun_login_context *ctx) {
  // set all fields to null
  memset(ctx, 0, sizeof *ctx);
  srun_login_setopt(ctx, SRLOPT_CLIENT_IP, "0.0.0.0");
  ctx->randnum = rand();
}

void srun_login_cleanup(srun_login_context *ctx) {
  free(ctx->username);
  free(ctx->password);
  free(ctx->client_ip);
  free(ctx->auth_server);
  free(ctx->chall);
  memset(ctx, 0, sizeof *ctx);
}

void srun_login_setopt(srun_login_context *ctx, srun_login_option option, ...) {
  va_list args;
  va_start(args, option);

  const char *src_str;

  switch (option) {
    case SRLOPT_USERNAME:
      src_str = va_arg(args, char *);
      ctx->username = checked_realloc(ctx->username, strlen(src_str) + 1);
      strcpy(ctx->username, src_str);
      break;
    case SRLOPT_PASSWORD:
      src_str = va_arg(args, char *);
      ctx->password = checked_realloc(ctx->password, strlen(src_str) + 1);
      strcpy(ctx->password, src_str);
      break;
    case SRLOPT_CLIENT_IP:
      src_str = va_arg(args, char *);
      ctx->client_ip = checked_realloc(ctx->client_ip, strlen(src_str) + 1);
      strcpy(ctx->client_ip, src_str);
      break;
    case SRLOPT_AUTH_SERVER:
      src_str = va_arg(args, char *);
      ctx->auth_server = checked_realloc(ctx->auth_server, strlen(src_str) + 1);
      strcpy(ctx->auth_server, src_str);
      break;
    case SRLOPT_AC_ID:
      ctx->ac_id = va_arg(args, int);
      break;
  }

  va_end(args);
}

void srun_login_perform(srun_login_context *ctx) {
  // retrieve challenge
  char url_buf[768];

  snprintf(url_buf, sizeof url_buf, "%s%s?username=%s&ip=%s&callback=jQuery_%d_0&_=%d", ctx->auth_server, PATH_GET_CHAL,
           ctx->username, ctx->client_ip, ctx->randnum, 0);

  char json_buf[512];
  curl_easy_setopt(curl, CURLOPT_URL, url_buf);
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, json_buf);

  CURLcode res;
  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    printf("libcurl error: %s(%d)\n", curl_easy_strerror(res), res);
    exit(1);
  }

  // locate the beginning of json
  cJSON *json = cJSON_Parse(strchr(json_buf, '{'));

  ctx->server_time = cJSON_GetObjectItem(json, "st")->valueint;

  srun_login_setopt(ctx, SRLOPT_CLIENT_IP, cJSON_GetObjectItem(json, "online_ip")->valuestring);

  const char *chall = cJSON_GetObjectItem(json, "challenge")->valuestring;
  const size_t chall_length = strlen(chall);

  ctx->chall = checked_realloc(ctx->chall, chall_length + 1);
  strncpy(ctx->chall, chall, chall_length);

  cJSON_Delete(json);

  char ac_id_buf[11];
  snprintf(ac_id_buf, 11, "%d", ctx->ac_id);

  // calculate challenge response
  // format info string
  json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "username", ctx->username);
  cJSON_AddStringToObject(json, "password", ctx->password);
  cJSON_AddStringToObject(json, "ip", ctx->client_ip);
  cJSON_AddStringToObject(json, "acid", ac_id_buf);
  cJSON_AddStringToObject(json, "enc_ver", "srun_bx1");

  const char *formatted = cJSON_PrintUnformatted(json);
  char info_buf[1024];
  size_t info_len = x_encode((const uint8_t *)formatted, strlen(formatted), (const uint8_t *)ctx->chall, chall_length,
                             (uint8_t *)info_buf, sizeof info_buf);
  cJSON_Delete(json);

  char b64_buf[1024] = "{SRBX1}";
  b64_encode((const uint8_t *)info_buf, info_len, b64_buf + strlen(b64_buf), sizeof b64_buf);

  char md5[33];
  unsigned int md_len;

  HMAC(EVP_md5(), ctx->chall, (int)chall_length, (const uint8_t *)ctx->password, strlen(ctx->password),
       (uint8_t *)md5 + 16, &md_len);
  for (int i = 0; i < md_len; i++) {
    snprintf(md5 + 2 * i, 3, "%02x", (uint8_t)md5[md_len + i]);
  }

  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  EVP_MD_CTX_init(hashctx);
  EVP_DigestInit(hashctx, EVP_sha1());
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, ctx->username, strlen(ctx->username));
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, md5, 32);
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, ac_id_buf, strlen(ac_id_buf));
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, ctx->client_ip, strlen(ctx->client_ip));
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, "200", 3);
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, "1", 1);
  EVP_DigestUpdate(hashctx, ctx->chall, chall_length);
  EVP_DigestUpdate(hashctx, b64_buf, strlen(b64_buf));

  char sha1_buf[41];
  EVP_DigestFinal(hashctx, (uint8_t *)sha1_buf + 20, &md_len);
  for (int i = 0; i < md_len; i++) {
    snprintf(sha1_buf + 2 * i, 3, "%02x", (uint8_t)sha1_buf[md_len + i]);
  }

  CURLU *curlu = curl_url();

  curl_url_set(curlu, CURLUPART_URL, ctx->auth_server, 0);
  curl_url_set(curlu, CURLUPART_PATH, PATH_PORTAL, 0);

  snprintf(url_buf, sizeof url_buf, "callback=jQuery%d_%ld000", ctx->randnum, ctx->server_time);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "action=login", CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "username=%s", ctx->username);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "password={MD5}%s", md5);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "ac_id=%d", ctx->ac_id);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "ip=%s", ctx->client_ip);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "chksum=%s", sha1_buf);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "info=%s", b64_buf);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "n=200", CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "type=1", CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "os=windows+10", CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "name=windows", CURLU_URLENCODE | CURLU_APPENDQUERY);
  curl_url_set(curlu, CURLUPART_QUERY, "double_stack=0", CURLU_URLENCODE | CURLU_APPENDQUERY);
  snprintf(url_buf, sizeof url_buf, "_=%ld000", ctx->server_time);
  curl_url_set(curlu, CURLUPART_QUERY, url_buf, CURLU_URLENCODE | CURLU_APPENDQUERY);

  char *part;
  curl_url_get(curlu, CURLUPART_URL, &part, 0);
  curl_free(part);

  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_perform(curl);

  curl_url_cleanup(curlu);
}

void srun_logout_perform(srun_login_context *ctx) {
  CURLU *curlu = curl_url();

  curl_url_set(curlu, CURLUPART_URL, ctx->auth_server, 0);
  curl_url_set(curlu, CURLUPART_PATH, PATH_PORTAL, 0);
  curl_url_set(curlu, CURLUPART_QUERY, "action=logout", CURLU_APPENDQUERY);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_perform(curl);

  curl_url_cleanup(curlu);
}

int main() {
  srand(time(NULL));

  srun_login_context ctx;
  srun_login_init(&ctx);

  printf("Username: ");
  char username[64];
  fgets(username, sizeof username, stdin);
  username[strlen(username) - 1] = 0;

  srun_login_setopt(&ctx, SRLOPT_USERNAME, username);
  srun_login_setopt(&ctx, SRLOPT_PASSWORD, getpass("Password: "));
  srun_login_setopt(&ctx, SRLOPT_AUTH_SERVER, SRUN_LOGIN_AUTH_URL);
  srun_login_setopt(&ctx, SRLOPT_AC_ID, SRUN_LOGIN_AC_ID);

  // printf("username = %s, password = %s, client_ip = %s, auth_server = %s\n", ctx.username, ctx.password, ctx.client_ip,
  //        ctx.auth_server);
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  srun_login_perform(&ctx);

  srun_login_cleanup(&ctx);

  curl_easy_cleanup(curl);
  curl_global_cleanup();
}
