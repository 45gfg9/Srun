#include "srun_login.h"
#include <string.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <openssl/evp.h>

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"

static inline uint8_t checked_subscript(const uint8_t *arr, size_t arr_len, size_t idx) {
  return idx < arr_len ? arr[idx] : 0;
}

static inline size_t x_max(size_t a, size_t b) {
  return a > b ? a : b;
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
  return msg_len / 4 + !!(msg_len % 4) + fixlen;
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

  uint32_t *encoded_msg = (uint32_t *)calloc(src_len / 4 + !!(src_len % 4) + 1, sizeof(uint32_t));
  uint32_t *encoded_key = (uint32_t *)calloc(x_max(4, key_len / 4 + !!(key_len % 4)), sizeof(uint32_t));

  size_t encoded_msg_len = s_encode(src, src_len, encoded_msg, 1);
  s_encode(key, key_len, encoded_key, 0);

  uint32_t n = src_len / 4 + !!(src_len % 4);
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
  for (size_t i = 0; i < 3 - src_len % 3; i++) {
    dst[retlen - 2 - i] = '=';
  }
  dst[retlen - 1] = '\0';

  return retlen;
}
