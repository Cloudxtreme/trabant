#include "skein.h"
#include "libscrypt.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void Skein1024_Process_Block(Skein1024_Ctxt_t *, const uint8_t *, size_t, size_t);

static void blkxor(uint8_t *output, const uint8_t *inputA, const uint8_t *inputB, const size_t input_sz) {
  size_t i;
  for (i = 0; i < input_sz; i++) {
    output[i] = inputA[i] ^ inputB[i];
  }
}

void skein_crypto_init(
    Skein1024_Ctxt_t *ctx, const size_t message_bit_sz,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz, 
    const uint8_t *personalization, const size_t personalization_sz) {
  Skein1024_Init(ctx, message_bit_sz);
  if (key && key_sz > 0) {
    Skein1024_Update(ctx, key, key_sz);
  }
  if (iv && iv_sz > 0) {
    Skein1024_Update(ctx, iv, key_sz);
  }
  if (personalization && personalization_sz > 0) {
    Skein1024_Update(ctx, personalization, personalization_sz);
  }
}

void skein_cipher_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *iv, const size_t iv_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  // 2^64-1 for message length as per Skein spec when running in CTR mode
  skein_crypto_init(ctxt, -1, key, key_sz, iv, iv_sz, personalization, personalization_sz);

  ctxt->h.T[1] |= SKEIN_T1_FLAG_FINAL;
  if (ctxt->h.bCnt < SKEIN1024_BLOCK_BYTES) {
    memset(&ctxt->b[ctxt->h.bCnt], 0, SKEIN1024_BLOCK_BYTES - ctxt->h.bCnt);
  }

  Skein1024_Process_Block(ctxt, ctxt->b, 1, ctxt->h.bCnt);

  memset(ctxt->b, 0, sizeof(ctxt->b));
}

void skein_xor_block(Skein1024_Ctxt_t *ctx, uint8_t *output, const uint8_t *input, const uint64_t offset) {
  uint64_t X[SKEIN1024_STATE_WORDS];

  // store counter mode key
  memcpy(X, ctx->X, sizeof(X));

  // build counter block
  uint64_t ctr = Skein_Swap64(offset);
  memcpy(ctx->b, &ctr, sizeof(uint64_t));
  Skein_Start_New_Type(ctx, OUT_FINAL);

  // run CTR mode
  Skein1024_Process_Block(ctx, ctx->b, 1, sizeof(uint64_t));

  // output CTR mode
  Skein_Put64_LSB_First(output, ctx->X, SKEIN1024_BLOCK_BYTES); 
  blkxor(output, input, output, SKEIN1024_BLOCK_BYTES);

  // restore counter mode key
  memcpy(ctx->X, X, sizeof(X));
}

void skein_hmac_init(
    Skein1024_Ctxt_t *ctxt,
    const uint8_t *key, const size_t key_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  skein_crypto_init(
      ctxt, SKEIN1024_STATE_BITS,
      key, key_sz,
      NULL, 0,
      personalization, personalization_sz);
}

void skein_hash_init(Skein1024_Ctxt_t *ctx, const uint8_t *personalization, const size_t personalization_sz) {
  skein_crypto_init(
      ctx, SKEIN1024_STATE_BITS,
      NULL, 0, 
      NULL, 0, 
      personalization, personalization_sz);
}

void skein_hash_update(Skein1024_Ctxt_t *ctx, const uint8_t *message, const size_t message_sz) {
  Skein1024_Update(ctx, message, message_sz);
}

void skein_hash_final(Skein1024_Ctxt_t *ctx, uint8_t *output) {
  Skein1024_Final(ctx, output);
}

void skein_hash_once(
    uint8_t *output, 
    const uint8_t *input, const size_t input_sz,
    const uint8_t *personalization, const size_t personalization_sz) {
  Skein1024_Ctxt_t ctx;
  skein_hash_init(&ctx, personalization, personalization_sz);
  skein_hash_update(&ctx, input, input_sz);
  skein_hash_final(&ctx, output);
}

int skein_pbkdf(
    uint8_t *output,
    const uint8_t *password, const size_t password_sz,
    const uint8_t *salt, const size_t salt_sz,
    const uint8_t *personalization, const size_t personalization_sz,
    uint64_t N, uint32_t r, uint32_t p) {
  uint8_t hashed_password[SKEIN1024_BLOCK_BYTES];
  uint8_t hashed_salt[SKEIN1024_BLOCK_BYTES];
  uint8_t pbkdf_output[32];

  skein_hash_once(hashed_password, password, password_sz, personalization, personalization_sz);
  skein_hash_once(hashed_salt, salt, salt_sz, personalization, personalization_sz);

  int result = libscrypt_scrypt(
      hashed_password, sizeof(hashed_password),
      hashed_salt, sizeof(hashed_salt),
      N, r, p,
      pbkdf_output, sizeof(pbkdf_output));

  if (result == 0) {
    skein_hash_once(output, pbkdf_output, sizeof(pbkdf_output), personalization, personalization_sz);
  }

  return result;
}
