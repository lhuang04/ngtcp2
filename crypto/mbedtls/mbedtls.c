/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <assert.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_mbedtls.h>

#include <mbedtls/ssl.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include "shared.h"

// All lengths are in bytes.
#define AES_128_ECB_BLKLEN 16
#define AES_128_GCM_KEYLEN 16
#define AES_128_GCM_KEYLEN_BITS (AES_128_GCM_KEYLEN << 3)
#define AES_128_GCM_TAGLEN 16
#define AES_128_GCM_NONCELEN 12
#define HP_MASK_LEN 5

static size_t crypto_aead_max_overhead(void *aead) {
  return AES_128_GCM_TAGLEN;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_init(&ctx->aead, NULL);
  ctx->md.native_handle = (void *)NULL;
  ctx->hp.native_handle = (void *)NULL;
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = crypto_aead_max_overhead(aead_native_handle);
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, NULL);
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  mbedtls_ssl_context *ssl = tls_native_handle;
  ngtcp2_crypto_aead_init(&ctx->aead, NULL);
  ctx->md.native_handle = (void *)NULL;
  ctx->hp.native_handle = (void *)NULL;
  ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
  ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return mbedtls_md_get_size(md->native_handle);
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return AES_128_GCM_KEYLEN;
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return AES_128_GCM_NONCELEN;
}

size_t ngtcp2_crypto_aead_taglen(const ngtcp2_crypto_aead *aead) {
  return AES_128_GCM_TAGLEN;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  mbedtls_gcm_context* gcm_ctx = calloc(1, sizeof(mbedtls_gcm_context));
  mbedtls_gcm_init(gcm_ctx);

  // key length in bits.
  if (mbedtls_gcm_setkey(
          gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, AES_128_GCM_KEYLEN_BITS) != 0) {
    goto cleanup;
  }
  aead_ctx->native_handle = gcm_ctx;
  return 0;

cleanup:
  if (gcm_ctx != NULL) {
    mbedtls_gcm_free(gcm_ctx);
    free(gcm_ctx);
  }
  return -1;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  mbedtls_gcm_context* gcm_ctx = calloc(1, sizeof(mbedtls_gcm_context));
  mbedtls_gcm_init(gcm_ctx);

  // key length in bits.
  if (mbedtls_gcm_setkey(
          gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, AES_128_GCM_KEYLEN_BITS) != 0) {
    goto cleanup;
  }
  aead_ctx->native_handle = gcm_ctx;
  return 0;

cleanup:
  if (gcm_ctx != NULL) {
    mbedtls_gcm_free(gcm_ctx);
    free(gcm_ctx);
  }
  return -1;
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  mbedtls_gcm_context* gcm_ctx = aead_ctx->native_handle;
  if (gcm_ctx != NULL) {
    mbedtls_gcm_free(gcm_ctx);
    free(gcm_ctx);
  }
}

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  mbedtls_aes_context* aes_ctx = calloc(1, sizeof(mbedtls_aes_context));
  mbedtls_aes_init(aes_ctx);

  // key length in bits.
  if (mbedtls_aes_setkey_enc(aes_ctx, key, AES_128_GCM_KEYLEN_BITS) != 0) {
    goto cleanup;
  }
  cipher_ctx->native_handle = aes_ctx;
  return 0;

cleanup:
  if (aes_ctx != NULL) {
    mbedtls_aes_free(aes_ctx);
    free(aes_ctx);
  }
  return -1;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  mbedtls_aes_context* aes_ctx = cipher_ctx->native_handle;
  if (aes_ctx != NULL) {
    mbedtls_aes_free(aes_ctx);
    free(aes_ctx);
  }
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  const mbedtls_md_info_t* md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  int rv = mbedtls_hkdf_extract(
      md_info,
      salt,
      saltlen,
      secret,
      secretlen,
      dest);

  return rv == 0 ? rv : -1;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  const mbedtls_md_info_t* md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  int rv = mbedtls_hkdf_expand(
      md_info,
      secret,
      secretlen,
      info,
      infolen,
      dest,
      destlen);

  return rv == 0 ? rv : -1;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen) {
  mbedtls_gcm_context* gcm_ctx = aead_ctx->native_handle;
  assert(gcm_ctx);

  // Obtain a pointer to a tag.
  uint8_t* tag = dest + plaintextlen;

  if (mbedtls_gcm_crypt_and_tag(
          gcm_ctx,
          MBEDTLS_GCM_ENCRYPT,
          plaintextlen,
          nonce,
          noncelen,
          ad,
          adlen,
          plaintext,
          dest,
          AES_128_GCM_TAGLEN,
          tag) != 0) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen) {
  if (ciphertextlen < AES_128_GCM_TAGLEN) {
    return -1;
  }

  ciphertextlen -= AES_128_GCM_TAGLEN;
  const uint8_t* tag = ciphertext + ciphertextlen;

  mbedtls_gcm_context* gcm_ctx = aead_ctx->native_handle;
  assert(gcm_ctx);

  if (mbedtls_gcm_auth_decrypt(
          gcm_ctx,
          ciphertextlen,
          nonce,
          noncelen,
          ad,
          adlen,
          tag,
          AES_128_GCM_TAGLEN,
          ciphertext,
          dest) != 0) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  mbedtls_aes_context* aes_ctx = hp_ctx->native_handle;
  assert(aes_ctx);
  uint8_t ecb_block[AES_128_ECB_BLKLEN];

  int rv =
      mbedtls_aes_crypt_ecb(aes_ctx, MBEDTLS_AES_ENCRYPT, sample, ecb_block);
  if (rv != 0) {
    return -1;
  }

  memcpy(dest, ecb_block, HP_MASK_LEN);

  return 0;
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn,
                                         ngtcp2_crypto_level crypto_level,
                                         const uint8_t *data, size_t datalen) {
  mbedtls_ssl_context *ssl = ngtcp2_conn_get_tls_native_handle(conn);
  int rv;

  if (mbedtls_quic_input_provide_data(ssl, ngtcp2_crypto_mbedtls_from_ngtcp2_crypto_level(crypto_level), data,
                            datalen) != 0) {
    return -1;
  }

  if (!ngtcp2_conn_get_handshake_completed(conn)) {
    while (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      rv = mbedtls_ssl_handshake_step(ssl);
      if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
        return 0;
      } else if (rv != 0) {
        return -1;
      }
    }
    ngtcp2_conn_handshake_completed(conn);
  }

  rv = mbedtls_ssl_quic_post_handshake(ssl);

  switch (rv) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case 0:
      return 0;
    default:
      return -1;
  }

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  mbedtls_ssl_context *ssl = tls;
  ngtcp2_transport_params_type exttype =
      ngtcp2_conn_is_server(conn)
          ? NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO
          : NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS;
  const uint8_t *tp;
  size_t tplen;
  ngtcp2_transport_params params;
  int rv;

  mbedtls_ssl_get_peer_quic_transport_params(ssl, &tp, &tplen);

  rv = ngtcp2_decode_transport_params(&params, exttype, tp, tplen);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  int rv = mbedtls_ssl_set_quic_transport_params(tls, buf, len);
  return rv == 0 ? rv : -1;
}

ngtcp2_crypto_level ngtcp2_crypto_mbedtls_from_ossl_encryption_level(
    mbedtls_ssl_crypto_level mbed_crypto_level) {
  switch (mbed_crypto_level) {
    case MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL:
      return NGTCP2_CRYPTO_LEVEL_INITIAL;
    case MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE:
      return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
    case MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION:
      return NGTCP2_CRYPTO_LEVEL_APPLICATION;
    default:
      // There is only one valid option left.
      assert (mbed_crypto_level == MBEDTLS_SSL_CRYPTO_LEVEL_EARLY_DATA);
      return NGTCP2_CRYPTO_LEVEL_EARLY;
  }
}

mbedtls_ssl_crypto_level
ngtcp2_crypto_mbedtls_from_ngtcp2_crypto_level(
    ngtcp2_crypto_level crypto_level) {
  switch (crypto_level ) {
    case NGTCP2_CRYPTO_LEVEL_INITIAL:
      return MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL;
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
      return MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE;
    case NGTCP2_CRYPTO_LEVEL_APPLICATION:
      return MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION;
    default:
      // There is only one valid option left.
      assert(crypto_level == NGTCP2_CRYPTO_LEVEL_EARLY);
      return MBEDTLS_SSL_CRYPTO_LEVEL_EARLY_DATA;
  }
}
