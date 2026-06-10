/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"
#define PATH_USER_DM "/cgi-bin/rad_user_dm"

#define CHALL_ENC_VER "srun_bx1"
#define CHALL_N "200"
#define CHALL_TYPE "1"

/**
 * @brief Encodes a message into a 32-bit integer array.
 * Original name "s"
 *
 * @param msg The message to encode.
 * @param msg_len The length of the message.
 * @param dst The destination array to hold the encoded message.
 * @param append_len If non-zero, appends the length of the message to the end of the encoded array.
 * @returns The number of 32-bit integers written to the destination array.
 */
static size_t s_encode(const uint8_t *msg, size_t msg_len, uint32_t *dst, int append_len) {
  // zero pad input
  size_t buf_len = ((msg_len + 3) / 4) * 4;
  uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
  if (!buf) {
    return 0;
  }
  memcpy(buf, msg, msg_len);

  size_t i;
  for (i = 0; i < msg_len; i += 4) {
    dst[i / 4] =
        ((uint32_t)buf[i + 3] << 24) | ((uint32_t)buf[i + 2] << 16) | ((uint32_t)buf[i + 1] << 8) | (uint32_t)buf[i];
  }
  free(buf);

  if (append_len) {
    dst[i / 4] = msg_len;
  }
  return i / 4 + !!append_len;
}

/**
 * @brief Decodes a message from a 32-bit integer array.
 * Original name "l"
 *
 * @param msg The encoded message as a 32-bit integer array.
 * @param msg_len The length of the encoded message (number of 32-bit integers).
 * @param dst The destination buffer to hold the decoded message.
 * @param dst_len The length of the destination buffer.
 * @param include_len If non-zero, checks the last element of the message for the actual length.
 * @returns The number of bytes written to the destination buffer, or 0 if an error occurred.
 */
static size_t s_decode(const uint32_t *msg, size_t msg_len, uint8_t *dst, size_t dst_len, int include_len) {
  size_t ret_len = msg_len * 4;

  if (include_len) {
    // the actual length is stored in the last element of the message
    ret_len = msg[msg_len - 1];

    // check if the length is valid
    uint32_t expected_len = (msg_len - 1) * 4;
    if (ret_len < expected_len - 3 || ret_len > expected_len) {
      // if the length recorded in the last element does not match
      // the actual length of the message, return 0
      return 0;
    }
  }

  if (ret_len > dst_len) {
    // dst is not large enough
    return 0;
  }

  for (size_t i = 0; i < ret_len; i++) {
    dst[i] = msg[i / 4] >> (i % 4 * 8);
  }

  return ret_len;
}

// original name "xEncode"
static size_t x_encode(const uint8_t *src, size_t src_len, const uint8_t *key, size_t key_len, uint8_t *dst,
                       size_t dst_len) {
  if (src_len == 0) {
    return 0;
  }

  if (key_len > 16) {
    // only at most 16 bytes of key are used
    key_len = 16;
  }

  uint32_t n = (src_len + 3) / 4 + 1;
  uint32_t *encoded_msg = malloc(n * sizeof(uint32_t));
  uint32_t encoded_key[4] = {0};

  if (!(encoded_msg && s_encode(src, src_len, encoded_msg, 1) && s_encode(key, key_len, encoded_key, 0))) {
    free(encoded_msg);
    return 0;
  }

  for (uint32_t d = 0, q = 6 + 52 / n; q; q--) {
    uint32_t z = encoded_msg[n - 1];
    d += 0x9e3779b9;
    for (uint32_t p = 0; p < n; p++) {
      uint32_t y = encoded_msg[(p + 1) % n];
      encoded_msg[p] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4 ^ d ^ y) + (encoded_key[(p ^ d >> 2) & 3] ^ z);
      z = encoded_msg[p];
    }
  }

  size_t ret_len = s_decode(encoded_msg, n, dst, dst_len, 0);

  free(encoded_msg);

  return ret_len;
}

/**
 * @brief Encodes a message into Base64 format.
 *
 * @param alpha The Base64 alphabet to use for encoding.
 * @param pad_char The character to use for padding (usually '=').
 * @param src The source message to encode.
 * @param src_len The length of the source message.
 * @param dst The destination buffer to hold the encoded message.
 * @param dst_len The length of the destination buffer.
 * @returns The number of bytes written to the destination buffer, including the trailing '\0'.
 */
static size_t b64_encode(const char alpha[64], char pad_char, const uint8_t *src, size_t src_len, char *dst,
                         size_t dst_len) {
  // check if the destination buffer is large enough
  size_t ret_len = ((src_len + 2) / 3) * 4 + 1;
  if (dst_len < ret_len) {
    return 0;
  }

  // zero pad input
  size_t buf_len = ((src_len + 2) / 3) * 3;
  uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
  if (!buf) {
    return 0;
  }
  memcpy(buf, src, src_len);

  // encode
  for (size_t i = 0; i < buf_len; i += 3) {
    uint32_t n = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2];
    for (int j = 0; j < 4; j++) {
      dst[(i / 3) * 4 + j] = alpha[(n >> (18 - j * 6)) & 0x3f];
    }
  }
  free(buf);

  // add padding characters if necessary
  size_t mod = src_len % 3;
  if (mod == 1) {
    dst[ret_len - 3] = pad_char;
    dst[ret_len - 2] = pad_char;
  } else if (mod == 2) {
    dst[ret_len - 2] = pad_char;
  }

  dst[ret_len - 1] = '\0';

  return ret_len;
}

static char *url_encode(const char *str) {
  if (!str) {
    errno = EINVAL;
    return NULL;
  }

  // allocate enough memory: worst case every char is encoded as %XX (3x)
  size_t len = strlen(str);
  char *enc = (char *)malloc(len * 3 + 1); // +1 for null terminator
  if (!enc) {
    return NULL;
  }

  char *penc = enc;

  for (; *str; str++) {
    unsigned char c = (unsigned char)*str;
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      *penc++ = c;
    } else {
      snprintf(penc, 4, "%%%02X", c);
      penc += 3;
    }
  }
  *penc = '\0';
  return enc;
}

/**
 * @brief Concatenates two URL parts, ensuring proper formatting.
 *
 * @param first The first part of the URL (base).
 * @param second The second part of the URL (path or absolute URL).
 * @returns A newly allocated string containing the concatenated URL, or NULL on error.
 * The caller is responsible for freeing the returned string.
 */
static char *url_concat(const char *first, const char *second) {
  // Input validation
  if (!first || !second) {
    errno = EINVAL;
    return NULL;
  }

  // If 'second' is an absolute URL with an http or https scheme, it replaces 'first'.
  if (strncmp(second, "http://", 7) == 0 || strncmp(second, "https://", 8) == 0) {
    return strdup(second);
  }

  // If 'first' starts with a slash or is empty, it's an error.
  if (first[0] == '/' || first[0] == '\0') {
    errno = EINVAL;
    return NULL;
  }

  // --- Determine the parts of the new URL ---

  const char *prefix = "";
  const char *base_part_start = first;
  const char *path_part_start = second;
  size_t base_part_len;
  size_t path_part_len = strlen(path_part_start);

  // Check if the 'first' URL has a scheme.
  int has_scheme = (strncmp(first, "http://", 7) == 0 || strncmp(first, "https://", 8) == 0);

  // If 'first' lacks a scheme, we'll prepend "http://".
  if (!has_scheme) {
    prefix = "http://";
  }

  // Determine the end of the base part from 'first'.
  const char *base_part_end;
  const char *first_end = first + strlen(first);

  if (second[0] == '/') {
    // If 'second' is an absolute path, the base is just the host of 'first'.
    const char *host_start = first;
    if (has_scheme) {
      const char *scheme_end = strstr(first, "://");
      if (scheme_end) {
        host_start = scheme_end + 3;
      }
    }
    const char *path_separator = strchr(host_start, '/');
    base_part_end = path_separator ? path_separator : first_end;

  } else {
    // If 'second' is a relative path.
    if (!has_scheme) {
      // If 'first' has no scheme, its path component is ignored.
      const char *path_separator = strchr(first, '/');
      base_part_end = path_separator ? path_separator : first_end;
    } else {
      // Otherwise, use the full path from 'first', stripping any query/fragment.
      const char *query_marker = strchr(first, '?');
      const char *fragment_marker = strchr(first, '#');

      if (query_marker && fragment_marker) {
        base_part_end = (query_marker < fragment_marker) ? query_marker : fragment_marker;
      } else if (query_marker) {
        base_part_end = query_marker;
      } else if (fragment_marker) {
        base_part_end = fragment_marker;
      } else {
        base_part_end = first_end;
      }
    }
  }

  base_part_len = base_part_end - base_part_start;

  // --- Normalize slashes between parts ---

  // Trim trailing slashes from the base part.
  while (base_part_len > 0 && base_part_start[base_part_len - 1] == '/') {
    base_part_len--;
  }

  // Trim leading slashes from the path part.
  while (path_part_len > 0 && path_part_start[0] == '/') {
    path_part_start++;
    path_part_len--;
  }

  // --- Allocate and construct the final string ---

  size_t prefix_len = strlen(prefix);
  // Total length = prefix + base + one '/' separator + path + null terminator.
  size_t final_len = prefix_len + base_part_len + 1 + path_part_len;
  char *result = (char *)malloc(final_len + 1);

  if (!result) {
    return NULL; // Allocation failed.
  }

  // Build the string piece by piece.
  char *p = result;
  memcpy(p, prefix, prefix_len);
  p += prefix_len;
  memcpy(p, base_part_start, base_part_len);
  p += base_part_len;
  *p++ = '/';
  memcpy(p, path_part_start, path_part_len);
  p += path_part_len;
  *p = '\0';

  return result;
}

srun_handle srun_create(srun_config *config) {
  if (!config || !config->base_url || !config->username) {
    errno = EINVAL;
    return NULL;
  }

  // allocate a new context
  srun_handle handle = (srun_handle)calloc(1, sizeof(struct srun_context));
  if (!handle) {
    return NULL;
  }

  if (!(handle->base_url = strdup(config->base_url)) || !(handle->username = strdup(config->username))
      || (config->password && !(handle->password = strdup(config->password)))
      || (config->cacert_pem && !(handle->cacert_pem = strdup(config->cacert_pem)))
      || (config->ip && !(handle->ip = strdup(config->ip)))
      || (config->if_name && !(handle->if_name = strdup(config->if_name)))) {
nomem_fail:
    srun_cleanup(handle);
    return NULL;
  }

  if (config->cacert_pem) {
    handle->cacert_len = config->cacert_len ? config->cacert_len : strlen(config->cacert_pem);
  } else if (config->cacert_path && !(handle->cacert_path = strdup(config->cacert_path))) {
    goto nomem_fail;
  }

  handle->ac_id = config->ac_id;
  handle->verbosity = config->verbosity;

  return handle;
}

void srun_cleanup(srun_handle handle) {
  if (handle->password) {
    memset(handle->password, 0, strlen(handle->password));
  }
  free(handle->if_name);
  free(handle->ip);
  free(handle->cacert_pem);
  free(handle->cacert_path);
  free(handle->password);
  free(handle->username);
  free(handle->base_url);
  free(handle);
}

static int json_strip_callback(char *buf) {
  char *json_start = strchr(buf, '{');
  char *json_end = strrchr(buf, '}');
  if (json_start && json_end && json_end > json_start) {
    memmove(buf, json_start, json_end - json_start + 1);
    buf[json_end - json_start + 1] = '\0';
    return 0;
  } else {
    return -1; // Invalid JSON format
  }
}

static int get_ac_id(const_srun_handle handle) {
  char *url = strdup(handle->base_url);
  int redirect_count = 0;
  const int max_redirects = 10; // Prevent infinite redirect loops

  while (redirect_count < max_redirects) {
    char *location = request_get_location(handle, url);

    if (location) {
      char *new_url = url_concat(url, location);
      free(location);
      location = new_url;
    }

    if (!location) {
      // some implementations use <meta http-equiv="refresh">, so try that
      srun_log_debug(handle->verbosity, "No Location header, trying to parse meta refresh\n");
      char *body = request_get_body(handle, url);
      if (body) {
        char *refresh_loc = strstr(body, "http-equiv=\"refresh\"");
        if (refresh_loc) {
          char *url_loc = strcasestr(refresh_loc, "url=");
          if (url_loc) {
            // skip "url="
            url_loc += 4;
            char *url_end = strpbrk(url_loc, "\"' \t\r\n");
            if (url_end) {
              *url_end = '\0';
            }
            // replace possible &amp;
            for (char *p = url_loc; p && *p;) {
              p = strstr(p, "&amp;");
              if (p) {
                memmove(p + 1, p + 5, strlen(p + 5) + 1);
              }
            }
            char *new_url = url_concat(url, url_loc);
            if (new_url) {
              location = new_url;
            }
          }
        }
        free(body);
      }
    }

    free(url);

    if (!location) {
      srun_log_error("Failed to guess ac_id. Login is very likely to fail.\n");
      return SRUN_AC_ID_GUESS;
    }
    srun_log_debug(handle->verbosity, "Location: %s\n", location);

    char *query = strchr(location, '?');
    if (query) {
      *query = '&'; // for easier parsing if ?ac_id=
      char *ac_id_str = strcasestr(query, "&ac_id=");
      if (ac_id_str) {
        int ac_id = (int)strtol(ac_id_str + 7, NULL, 10);
        free(location);
        srun_log_verbose(handle->verbosity, "Guessed ac_id: %d\n", ac_id);
        return ac_id;
      }
    }

    url = location;
    redirect_count++;
  }

  srun_log_error("Too many redirects while trying to guess ac_id.\n");
  free(url);
  return SRUN_AC_ID_GUESS;
}

static int get_challenge(struct chall_response *chall, const_srun_handle handle) {
  // callback parameter serves no purpose
  const unsigned long long req_time = time(NULL);
  static const char chall_fmtstr[] = "%s" PATH_GET_CHAL "?callback=jQuery98"
                                     "&username=%s&ip=%s&_=%llu000";
  const char *client_ip = handle->ip ? handle->ip : "";
  char *chall_url;
  if (asprintf(&chall_url, chall_fmtstr, handle->base_url, handle->username, client_ip, req_time) == -1) {
    return SRUNE_SYSTEM;
  }
  srun_log_debug(handle->verbosity, "Challenge URL: %s\n", chall_url);
  char *resp_buf = request_get_body(handle, chall_url);
  free(chall_url);

  if (!resp_buf) {
    srun_log_error("Failed to get challenge response\n");
    return SRUNE_NETWORK;
  }
  srun_log_verbose(handle->verbosity, "Challenge response: %s\n", resp_buf);

  if (json_strip_callback(resp_buf) != 0 || parse_chall_response(chall, resp_buf) != 0) {
    srun_log_error("Invalid challenge response: %s\n", resp_buf);
    free(resp_buf);
    return SRUNE_NETWORK;
  }
  free(resp_buf);
  return SRUNE_OK;
}

static int get_portal(struct portal_response *chall, const_srun_handle handle, const char *url) {
  srun_log_debug(handle->verbosity, "Portal URL: %s\n", url);
  char *resp_buf = request_get_body(handle, url);

  if (!resp_buf) {
    srun_log_error("Failed to get portal response\n");
    return SRUNE_NETWORK;
  }
  srun_log_verbose(handle->verbosity, "Portal response: %s\n", resp_buf);

  if (json_strip_callback(resp_buf) != 0 || parse_portal_response(chall, resp_buf) != 0) {
    srun_log_error("Invalid portal response: %s\n", resp_buf);
    free(resp_buf);
    return SRUNE_NETWORK;
  }
  free(resp_buf);
  return SRUNE_OK;
}

int srun_login(srun_handle handle) {
  if (!handle->password) {
    return SRUNE_INVALID_CTX;
  }

  // 1. if ac_id is not set, try to get it from the server
  if (handle->ac_id == SRUN_AC_ID_GUESS) {
    handle->ac_id = get_ac_id(handle);
  }

  // 2. get challenge response
  struct chall_response chall;
  int retval = get_challenge(&chall, handle);
  if (retval != SRUNE_OK) {
    return retval;
  }

  const size_t token_len = strlen(chall.token);

  // 3. if ip is not set, use the one from challenge response
  if (!handle->ip) {
    handle->ip = chall.client_ip;
    chall.client_ip = NULL; // prevent double free
  }

  // 4. construct challenge response

  // 4.1. HMAC-MD5 of the user password
  uint8_t hmac_md5_buf[16];
  char hmac_md5_hex[33];

  hmac_md5_digest((const uint8_t *)handle->password, strlen(handle->password), (const uint8_t *)chall.token, token_len,
                  hmac_md5_buf);
  for (unsigned int i = 0; i < 16; i++) {
    snprintf(&hmac_md5_hex[2 * i], 3, "%02hhx", hmac_md5_buf[i]);
  }

  // 4.2. info field
  char *const info_str = create_info_field(handle, CHALL_ENC_VER);
  if (!info_str) {
nomem_free_chall:
    free_chall_response(&chall);
    return SRUNE_SYSTEM;
  }
  const size_t info_str_len = strlen(info_str);

  // 4.3. x_encode the info field
  const size_t xenc_info_len = ((info_str_len + 3) / 4 + 1) * 4;
  uint8_t *xenc_info = (uint8_t *)malloc(xenc_info_len);
  if (!xenc_info) {
    free(info_str);
    goto nomem_free_chall;
  }
  x_encode((const uint8_t *)info_str, info_str_len, (const uint8_t *)chall.token, token_len, xenc_info, xenc_info_len);
  free(info_str);

  // 4.4. Base64 encode the xenc_info
  const size_t b64enc_info_len = ((xenc_info_len + 2) / 3) * 4;
  char *const b64enc_info = (char *)malloc(8 + b64enc_info_len); // "{SRBX1}" + '\0'
  if (!b64enc_info) {
    free(xenc_info);
    goto nomem_free_chall;
  }
  strcpy(b64enc_info, "{SRBX1}");
  b64_encode("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA", '=', xenc_info, xenc_info_len,
             b64enc_info + 7, b64enc_info_len + 1);
  free(xenc_info);

  // 4.5. the SHA-1 checksum
  char ac_id_str[12];
  snprintf(ac_id_str, sizeof ac_id_str, "%d", handle->ac_id);

  char *sha1_msg;
  int sha1_msg_len = asprintf(&sha1_msg, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s", chall.token, handle->username, chall.token,
                              hmac_md5_hex, chall.token, ac_id_str, chall.token, handle->ip, chall.token, CHALL_N,
                              chall.token, CHALL_TYPE, chall.token, b64enc_info);
  if (sha1_msg_len == -1) {
    free(b64enc_info);
    goto nomem_free_chall;
  }
  free_chall_response(&chall);

  uint8_t sha1_buf[20];
  char sha1_hex[41];
  sha1_digest((const uint8_t *)sha1_msg, sha1_msg_len, sha1_buf);
  free(sha1_msg);
  for (unsigned int i = 0; i < sizeof sha1_buf; i++) {
    snprintf(&sha1_hex[2 * i], 3, "%02hhx", sha1_buf[i]);
  }

  // 5. construct portal request URL
  char *url_encoded_info = url_encode(b64enc_info);
  free(b64enc_info);
  if (!url_encoded_info) {
    goto nomem_free_chall;
  }

  const unsigned long long req_time = time(NULL);
  static const char portal_fmtstr[] = "%s" PATH_PORTAL "?callback=jQuery98&n=%s&type=%s&_=%llu000"
                                      "&username=%s&password=%%7BMD5%%7D%s&ac_id=%d&ip=%s&chksum=%s&info=%s"
                                      "&action=login&os=Linux&name=Linux&double_stack=0";
  char *portal_url;
  if (asprintf(&portal_url, portal_fmtstr, handle->base_url, CHALL_N, CHALL_TYPE, req_time, handle->username,
               hmac_md5_hex, handle->ac_id, handle->ip, sha1_hex, url_encoded_info)
      == -1) {
    free(url_encoded_info);
    goto nomem_free_chall;
  }
  free(url_encoded_info);

  // 6. perform portal request
  struct portal_response resp;
  retval = get_portal(&resp, handle, portal_url);
  free(portal_url);
  if (retval != SRUNE_OK) {
    return retval;
  }

  if (strcmp(resp.error, "ok") == 0) {
    // login successful
    free_portal_response(&resp);
    return SRUNE_OK;
  }

  srun_log_error("%s", resp.error);
  if (resp.ecode[0]) {
    srun_log_error(" (%s)", resp.ecode);
  }
  if (resp.error_msg[0]) {
    srun_log_error(": %s", resp.error_msg);
  }
  srun_log_error("\n");
  free_portal_response(&resp);
  return SRUNE_NETWORK;
}

int srun_logout(srun_handle handle) {
  const unsigned long long req_time = time(NULL);

  // 1. get client_ip from challenge response if not set, required by logout
  char *client_ip;
  if (handle->ip && handle->ip[0]) {
    client_ip = strdup(handle->ip);
  } else {
    struct chall_response chall;
    int retval = get_challenge(&chall, handle);
    if (retval != SRUNE_OK) {
      return retval;
    }
    client_ip = chall.client_ip;
    chall.client_ip = NULL;
    free_chall_response(&chall);
  }

  // 2. calculate dm SHA1 sign
  // sign = SHA1(time | username | ip | '1' | time)
  char *sign_str;
  int sign_str_len = asprintf(&sign_str, "%llu%s%s1%llu", req_time, handle->username, client_ip, req_time);
  if (sign_str_len == -1) {
nomem_free_ip:
    free(client_ip);
    return SRUNE_SYSTEM; // memory allocation failed
  }
  uint8_t sha1_buf[20];
  char sha1_hex[41];
  sha1_digest((const uint8_t *)sign_str, strlen(sign_str), sha1_buf);
  for (unsigned int i = 0; i < sizeof sha1_buf; i++) {
    snprintf(&sha1_hex[2 * i], 3, "%02hhx", sha1_buf[i]);
  }
  free(sign_str);

  // 3. construct logout request URL
  static const char logout_fmtstr[] = "%s" PATH_USER_DM "?callback=jQuery98&ip=%s&username=%s&time=%llu"
                                      "&unbind=1&sign=%s&_=%llu000";
  char *logout_url;
  if (asprintf(&logout_url, logout_fmtstr, handle->base_url, client_ip, handle->username, req_time, sha1_hex, req_time)
      == -1) {
    goto nomem_free_ip;
  }
  free(client_ip);

  // 4. perform logout request
  struct portal_response resp;
  int retval = get_portal(&resp, handle, logout_url);
  free(logout_url);
  if (retval != SRUNE_OK) {
    return retval;
  }

  if (strcmp(resp.error, "ok") == 0 || strcmp(resp.error, "not_online_error") == 0) {
    // logout successful
    free_portal_response(&resp);
    return SRUNE_OK;
  }

  srun_log_error("%s", resp.error);
  if (resp.ecode[0]) {
    srun_log_error(" (%s)", resp.ecode);
  }
  if (resp.error_msg[0]) {
    srun_log_error(": %s", resp.error_msg);
  }
  srun_log_error("\n");
  free_portal_response(&resp);
  return SRUNE_NETWORK;
}
