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

#include "tls_client_context_mbedtls.h"
#include "client_base.h"
#include "template.h"
#include "util.h"

TLSClientSession::TLSClientSession() {}

TLSClientSession::~TLSClientSession() {}

extern Config config;

int TLSClientSession::init(bool &early_data_enabled,
                           const TLSClientContext &tls_ctx,
                           const char *remote_addr, ClientBase *client,
                           AppProtocol app_proto) {
  early_data_enabled = false;

  auto ssl_ctx = tls_ctx.get_native_handle();

  ssl_ = SSL_new(ssl_ctx);
  SSL_set_app_data(ssl_, client);
  SSL_set_connect_state(ssl_);

  switch (app_proto) {
  case AppProtocol::H3: {
    auto alpn = reinterpret_cast<const uint8_t *>(H3_ALPN);
    auto alpnlen = str_size(H3_ALPN);
    SSL_set_alpn_protos(ssl_, alpn, alpnlen);
    break;
  }
  case AppProtocol::HQ: {
    auto alpn = reinterpret_cast<const uint8_t *>(HQ_ALPN);
    auto alpnlen = str_size(HQ_ALPN);
    SSL_set_alpn_protos(ssl_, alpn, alpnlen);
    break;
  }
  case AppProtocol::Perf:
    /* TODO Not implemented yet */
    assert(0);
    break;
  }

  if (!config.sni.empty()) {
    SSL_set_tlsext_host_name(ssl_, config.sni.data());
  } else if (util::numeric_host(remote_addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    SSL_set_tlsext_host_name(ssl_, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl_, remote_addr);
  }

  if (config.session_file) {
    auto f = BIO_new_file(config.session_file, "r");
    if (f == nullptr) {
      std::cerr << "Could not read TLS session file " << config.session_file
                << std::endl;
    } else {
      auto session = PEM_read_bio_SSL_SESSION(f, nullptr, 0, nullptr);
      BIO_free(f);
      if (session == nullptr) {
        std::cerr << "Could not read TLS session file " << config.session_file
                  << std::endl;
      } else {
        if (!SSL_set_session(ssl_, session)) {
          std::cerr << "Could not set session" << std::endl;
        } else if (!config.disable_early_data &&
                   SSL_SESSION_get_max_early_data(session)) {
          early_data_enabled = true;
          SSL_set_quic_early_data_enabled(ssl_, 1);
        }
        SSL_SESSION_free(session);
      }
    }
  }

  return 0;
}

bool TLSClientSession::get_early_data_accepted() const {
  // SSL_get_early_data_status works after handshake completes.
  return SSL_get_early_data_status(ssl_) == SSL_EARLY_DATA_ACCEPTED;
}
