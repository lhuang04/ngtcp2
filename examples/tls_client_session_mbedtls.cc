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
#include "tls_client_session_mbedtls.h"

#include <cassert>
#include <iostream>

#include <ngtcp2/ngtcp2_crypto_mbedtls.h>

#include "tls_client_context_mbedtls.h"
#include "client_base.h"
#include "template.h"
#include "util.h"

TLSClientSession::TLSClientSession() {}

TLSClientSession::~TLSClientSession() {}

extern Config config;

namespace {
int set_encryption_secrets(void* ctx, mbedtls_ssl_crypto_level l,
                           const uint8_t *read_secret,
                           const uint8_t *write_secret, size_t secret_len) {
  ClientBase* c = (ClientBase*) ctx;
  auto level = ngtcp2_crypto_mbedtls_from_ossl_encryption_level(l);

  if (read_secret) {
    if (c->on_rx_key(level, read_secret, secret_len) != 0) {
      return -1;
    }

    if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
        c->call_application_rx_key_cb() != 0) {
      return -1;
    }
  }

  if (c->on_tx_key(level, write_secret, secret_len) != 0) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int add_handshake_data(void* ctx, mbedtls_ssl_crypto_level l,
                       const uint8_t *data, size_t len) {
  ClientBase* c = (ClientBase*) ctx;
  auto level = ngtcp2_crypto_mbedtls_from_ossl_encryption_level(l);
  c->write_client_handshake(level, data, len);
  return 0;
}
} // namespace

namespace {
void process_new_session(void* callbackParam, mbedtls_ssl_session* ticket)
{
}
} // namespace

namespace {
int send_alert(void* ctx, mbedtls_ssl_crypto_level level, uint8_t alert) {
  ClientBase* c = (ClientBase*) ctx;
  c->set_tls_alert(alert);
  return 0;
}
} // namespace

namespace {
auto quic_method = mbedtls_quic_method{
    set_encryption_secrets,
    add_handshake_data,
    send_alert,
    process_new_session,
};

mbedtls_ssl_context _ssl;
} // namespace

int TLSClientSession::init(bool &early_data_enabled,
                           const TLSClientContext &tls_ctx,
                           const char *remote_addr, ClientBase *client,
                           AppProtocol app_proto) {
  early_data_enabled = false;
  auto ssl_ctx = tls_ctx.get_native_handle();

  ssl_ = &_ssl;
  mbedtls_ssl_init(ssl_);
  mbedtls_ssl_setup(ssl_, ssl_ctx);
  mbedtls_ssl_set_hs_quic_method(
      ssl_, client, &quic_method);

  if (!config.sni.empty()) {
    mbedtls_ssl_set_hostname(ssl_, config.sni.data());
  } else if (util::numeric_host(remote_addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    mbedtls_ssl_set_hostname(ssl_, "localhost");
  } else {
    mbedtls_ssl_set_hostname(ssl_, remote_addr);
  }

  return 0;
}

bool TLSClientSession::get_early_data_accepted() const {
  // SSL_get_early_data_status works after handshake completes.
  return mbedtls_ssl_get_early_data_status(ssl_) == MBEDTLS_SSL_EARLY_DATA_ACCEPTED;
}
