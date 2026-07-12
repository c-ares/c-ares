/* MIT License
 *
 * Copyright (c) 2026 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef ARES_TEST_TLS_SERVER_H
#define ARES_TEST_TLS_SERVER_H

#include "ares_setup.h"
#include "ares.h"

#ifdef CARES_USE_CRYPTO

#  include <memory>
#  include <string>
#  include <vector>

namespace ares {
namespace test {

/* The DNS name embedded in the mock DoT server certificate's subjectAltName,
 * so strict-verification tests can present a matching (or deliberately
 * mismatched) authentication name. */
static const char * const kMockDoTHostname = "dot.example.com";

/* Server-side TLS termination for the mock DoT server.
 *
 * Driven entirely by in-memory buffers so it fits the single-threaded,
 * event-driven MockServer -- no background thread and no blocking socket I/O
 * inside the TLS layer.  It is implemented with whichever crypto backend
 * c-ares was built against (OpenSSL or Schannel), so exercising the Schannel
 * client backend needs no OpenSSL, and vice versa. */
class TlsServerConn {
public:
  virtual ~TlsServerConn()
  {
  }

  /* Feed ciphertext that was read from the socket. */
  virtual void FeedCipher(const unsigned char *data, size_t len) = 0;

  /* Remove and return ciphertext the endpoint wants written to the socket. */
  virtual std::vector<unsigned char> DrainCipher() = 0;

  /* Drive the handshake using whatever ciphertext has been fed.  Returns true
   * once established.  On unrecoverable error sets *fatal = true. */
  virtual bool Handshake(bool *fatal) = 0;

  virtual bool Established() const = 0;

  /* Decrypt buffered application plaintext (post-handshake), appending to
   * *out.  Sets *closed = true if the peer sent a close-notify.  Returns
   * false on a fatal protocol error. */
  virtual bool ReadPlain(std::vector<unsigned char> *out, bool *closed) = 0;

  /* Encrypt application plaintext; the ciphertext becomes available via
   * DrainCipher(). */
  virtual bool WritePlain(const unsigned char *data, size_t len) = 0;

  /* Whether this connection's handshake resumed a prior TLS session (rather
   * than performing a full handshake).  Only meaningful once established. */
  virtual bool WasResumed() = 0;
};

class TlsServerCtx {
public:
  virtual ~TlsServerCtx()
  {
  }

  /* New per-connection server endpoint. */
  virtual std::unique_ptr<TlsServerConn> NewConn() = 0;

  /* The trust anchor (CA, or self-signed server cert) in PEM form, for
   * injecting into the client's trust store via ares_tls_set_cadata() so
   * strict verification succeeds. */
  virtual std::string CaPEM() const = 0;

  /* Create a context backed by the compiled-in crypto backend.  Returns
   * nullptr on failure. */
  static std::unique_ptr<TlsServerCtx> Create();
};

}  // namespace test
}  // namespace ares

#endif /* CARES_USE_CRYPTO */
#endif /* ARES_TEST_TLS_SERVER_H */
