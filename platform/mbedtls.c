/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <mbedtls/md.h>

inline size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[static 20]) {
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), data, len, digest);
  return 20;
}

inline size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                              uint8_t digest[static 16]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), key, key_len, data, data_len, digest);
  return 16;
}
