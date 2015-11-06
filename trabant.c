#include "pkc_skein.h"
#include <string.h>

size_t skein_context_size_js(void) {
  return sizeof(Skein1024_Ctxt_t);
}

void skein_cipher_init_js(
    uint8_t *ctxt_buf,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz,
    int legacy) {
  Skein1024_Ctxt_t ctxt;
  skein_cipher_init(&ctxt,
      key, key_sz, 
      iv, iv_sz, 
      CIPHER_PERS, CIPHER_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_xor_block_js(
    uint8_t *ctxt_buf,
    uint8_t *output,
    const uint8_t *input,
    const uint64_t offset) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_xor_block(&ctxt, output, input, offset);
}

void skein_hash_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  skein_hash_init(&ctxt, HASH_PERS, HASH_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hmac_init_js(uint8_t *ctxt_buf, const uint8_t *key, const size_t key_sz) {
  Skein1024_Ctxt_t ctxt;
  skein_hmac_init(&ctxt, key, key_sz, HMAC_PERS, HMAC_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hash_update_js(uint8_t *ctxt_buf, const uint8_t *message, const size_t message_sz) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_hash_update(&ctxt, message, message_sz);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void skein_hash_final_js(uint8_t *ctxt_buf, uint8_t *output) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  skein_hash_final(&ctxt, output);
}

void skein_hash_once_js(
    uint8_t *output, 
    const uint8_t *input, const size_t input_sz) {
  skein_hash_once(output, input, input_sz, HASH_PERS, HASH_PERS_SZ);
}

int skein_pbkdf_js(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    uint64_t N, uint32_t r, uint32_t p) {
  return skein_pbkdf(
      output, 
      password, password_sz,
      salt, salt_sz,
      PBKDF_PERS, PBKDF_PERS_SZ,
      N, r, p);
}

#ifdef LEGACY_SUPPORT

void LEGACY_skein_cipher_init_js(
    uint8_t *ctxt_buf, const size_t message_bit_sz,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_cipher_init(
      &ctxt, message_bit_sz, 
      key, key_sz, 
      iv, iv_sz, 
      CIPHER_PERS, CIPHER_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_xor_block_js(uint8_t *ctxt_buf, uint8_t *output, const uint8_t *input, const uint64_t offset) {
  Skein1024_Ctxt_t ctxt;
  memcpy(&ctxt, ctxt_buf, sizeof(Skein1024_Ctxt_t));
  LEGACY_skein_xor_block(&ctxt, output, input, offset);
}

void LEGACY_skein_hash_once_js(
    uint8_t *output, 
    const uint8_t *input, const size_t input_sz) {
  LEGACY_skein_hash_once(output, input, input_sz, HASH_PERS, HASH_PERS_SZ);
}

void LEGACY_skein_pbkdf_js(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    const uint8_t work) {
  LEGACY_skein_pbkdf(
      output, 
      password, password_sz, 
      salt, salt_sz,
      PBKDF_PERS, PBKDF_PERS_SZ, 
      work);
}

void LEGACY_skein_pbkdf_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_pbkdf_init(&ctxt, PBKDF_PERS, PBKDF_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_hash_init_js(uint8_t *ctxt_buf) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_hash_init(&ctxt, HASH_PERS, HASH_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

void LEGACY_skein_hmac_init_js(uint8_t *ctxt_buf, const uint8_t *key, const size_t key_sz) {
  Skein1024_Ctxt_t ctxt;
  LEGACY_skein_hmac_init(&ctxt, key, key_sz, HMAC_PERS, HMAC_PERS_SZ);
  memcpy(ctxt_buf, &ctxt, sizeof(Skein1024_Ctxt_t));
}

#endif
