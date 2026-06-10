/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <psa/crypto.h>

inline size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[static 20]) {
  size_t hash_len;
  psa_hash_compute(PSA_ALG_SHA_1, data, len, digest, 20, &hash_len);
  return hash_len;
}

inline size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                              uint8_t digest[static 16]) {
  psa_status_t status;
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t key_id = PSA_KEY_ID_NULL;

  status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    return 0;
  }

  psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attrs, key_len * 8);
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_MD5));

  status = psa_import_key(&attrs, key, key_len, &key_id);
  psa_reset_key_attributes(&attrs);
  if (status != PSA_SUCCESS) {
    return 0;
  }

  size_t hash_len;
  psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_MD5), data, data_len, digest, 16, &hash_len);
  psa_destroy_key(key_id);
  return hash_len;
}
