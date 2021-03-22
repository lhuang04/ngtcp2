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
#include "util.h"

#include <cassert>
#include <iostream>
#include <array>

#include <ngtcp2/ngtcp2_crypto.h>

#include <mbedtls/ssl.h>

#include "template.h"

namespace ngtcp2 {

namespace util {

namespace {
auto randgen = make_mt19937();
} // namespace

int generate_secret(uint8_t *secret, size_t secretlen) {
  std::array<uint8_t, 32> md;
  assert(md.size() == secretlen);

  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate_n(md.data(), md.size(), [&dis]() { return dis(randgen); });

  std::copy_n(std::begin(md), secretlen, secret);
  return 0;
}

std::optional<std::string> read_token(const std::string_view &filename) {
  auto res = "";
  return res;
}

int write_token(const std::string_view &filename, const uint8_t *token,
                size_t tokenlen) {
  return 0;
}

ngtcp2_crypto_md crypto_md_sha256() {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, NULL);
  return md;
}

const char *crypto_default_ciphers() {
  return "TLS_AES_128_GCM_SHA256";
}

const char *crypto_default_groups() { return "X25519"; }

} // namespace util

} // namespace ngtcp2
