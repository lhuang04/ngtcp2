/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
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
#include "tls_client_context_mbedtls.h"

#include <iostream>
#include <fstream>

#include <ngtcp2/ngtcp2_crypto_mbedtls.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>

#include "client_base.h"
#include "template.h"

extern Config config;

TLSClientContext::TLSClientContext() : ssl_ctx_{nullptr} {}

TLSClientContext::~TLSClientContext() {
  if (ssl_ctx_) {
    mbedtls_ssl_config_free(ssl_ctx_);
  }
}

mbedtls_ssl_config *TLSClientContext::get_native_handle() const { return ssl_ctx_; }

namespace {
mbedtls_ssl_config _mbedTlsConfig;
mbedtls_ctr_drbg_context _mbedTlsCtrDrbg;
mbedtls_entropy_context _mbedTlsEntropy;

void _HandshakeDebugPrint(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* msg) {
  fprintf(stderr, "mbedDBG[%d]: %s:%d %s", level, file, line, msg);
}

int kSSLPresetQUICCiphersuites[] = {TLS_AES_128_GCM_SHA256, 0};

mbedtls_ecp_group_id kSSLPresetQUICCurves[] = {
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_NONE};

const char* alpns[] = {"h3-fb-05", "h3-29", 0};

const unsigned char PSEUDORANDOM_TAG[] = "mobilenetwork";
mbedtls_ssl_config *create_ssl_ctx(const char *private_key_file, const char *cert_file) {
  mbedtls_ssl_config_init(&_mbedTlsConfig);
  mbedtls_ssl_config_defaults(
      &_mbedTlsConfig,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_QUIC,
      MBEDTLS_SSL_PRESET_DEFAULT);
  mbedtls_ssl_conf_min_version(
      &_mbedTlsConfig,
      MBEDTLS_SSL_MAJOR_VERSION_3,
      MBEDTLS_SSL_MINOR_VERSION_4);
  mbedtls_ssl_conf_max_version(
      &_mbedTlsConfig,
      MBEDTLS_SSL_MAJOR_VERSION_3,
      MBEDTLS_SSL_MINOR_VERSION_4);
  mbedtls_ssl_conf_ciphersuites(
      &_mbedTlsConfig, kSSLPresetQUICCiphersuites);
  mbedtls_ssl_conf_key_share_curves(
      &_mbedTlsConfig, kSSLPresetQUICCurves);
  mbedtls_ssl_conf_curves(&_mbedTlsConfig, kSSLPresetQUICCurves);
  // Initialize counter mode DRBG (NOTE: do we need DRBG for GCM mode)?
  mbedtls_ctr_drbg_init(&_mbedTlsCtrDrbg);
  // Initialize the entropy source for the DRBG.
  mbedtls_entropy_init(&_mbedTlsEntropy);
  // Initialize the pseudo random number generator.
  mbedtls_ssl_conf_rng(
      &_mbedTlsConfig, mbedtls_ctr_drbg_random, &_mbedTlsCtrDrbg);

  // Allow any key exchanges
  mbedtls_ssl_conf_tls13_key_exchange(
      &_mbedTlsConfig, MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_ALL);

  // Seed the DRBG for the first time and setup entropy source
  // for future reseeds.
  assert(
      mbedtls_ctr_drbg_seed(
          &_mbedTlsCtrDrbg,
          mbedtls_entropy_func,
          &_mbedTlsEntropy,
          PSEUDORANDOM_TAG,
          sizeof(PSEUDORANDOM_TAG)) == 0);

  mbedtls_ssl_conf_authmode(&_mbedTlsConfig, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_debug_set_threshold(5);
  mbedtls_ssl_conf_dbg(&_mbedTlsConfig, _HandshakeDebugPrint, NULL);
  mbedtls_ssl_conf_alpn_protocols(&_mbedTlsConfig, alpns);
  return &_mbedTlsConfig;
}
} // namespace

int TLSClientContext::init(const char *private_key_file,
                           const char *cert_file) {
  ssl_ctx_ = create_ssl_ctx(private_key_file, cert_file);
  return ssl_ctx_ != NULL? 0 : -1;
}

void TLSClientContext::enable_keylog() {
}
