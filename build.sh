#!/bin/bash

FUNCTIONS="[
'_crypto_box_curve25519xsalsa20poly1305_tweet_keypair',
'_crypto_box_curve25519xsalsa20poly1305_tweet_beforenm',
'_crypto_box_curve25519xsalsa20poly1305_tweet_afternm',
'_crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm',
'_crypto_onetimeauth_poly1305_tweet',
'_crypto_onetimeauth_poly1305_tweet_verify',
'_crypto_sign_ed25519_tweet',
'_crypto_sign_ed25519_tweet_open',
'_crypto_sign_ed25519_tweet_keypair',
'_malloc',
'_calloc',
'_free',
'_memset',
'_memcpy',
'cwrap',

'_skein_context_size_js',
'_skein_hash_update_js',
'_skein_hash_final_js',

'_skein_cipher_init_js',
'_skein_xor_block_js',

'_skein_hash_init_js',
'_skein_hmac_init_js',

'_skein_hash_once_js',
'_skein_pbkdf_js',

'_LEGACY_skein_cipher_init_js',
'_LEGACY_skein_xor_block_js',
'_LEGACY_skein_hmac_init_js',
'_LEGACY_skein_pbkdf_js',
'_LEGACY_skein_hash_once_js',
]"

emcc \
  -DLEGACY_SUPPORT \
  -Wall -pedantic \
  -O3 \
  -Iskein \
  -Iscrypt \
  --llvm-lto 3 \
  --closure 1 \
  --memory-init-file 0 \
  -s ASSERTIONS=1 \
  -s AGGRESSIVE_VARIABLE_ELIMINATION=1 \
  -s USE_CLOSURE_COMPILER=1 \
  -s TOTAL_MEMORY=67108864 \
  -s NO_EXIT_RUNTIME=1 \
  -s EXPORTED_FUNCTIONS="${FUNCTIONS}" \
  -s ALLOW_MEMORY_GROWTH=0 \
  --js-library randombytes.js \
  -o trabant.min.js \
  -DHAVE_CONFIG_H \
  scrypt/crypto_scrypt-nosse.c scrypt/sha256.c \
  skein/skein_block.c skein/skein.c \
  tweetnacl.c \
  pkc_skein.c \
  trabant.c

cp trabant.min.js ../web/app/static/js
