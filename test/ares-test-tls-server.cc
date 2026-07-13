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

#include "ares-test-tls-server.h"

#ifdef CARES_USE_CRYPTO

/* ========================================================================= *
 * OpenSSL server-side TLS backend (memory-BIO driven, non-blocking)
 * ========================================================================= */
#  ifdef CARES_CRYPTO_OPENSSL

#    include <openssl/ssl.h>
#    include <openssl/bio.h>
#    include <openssl/pem.h>
#    include <openssl/x509v3.h>
#    include <openssl/evp.h>
#    include <openssl/err.h>

namespace ares {
namespace test {

namespace {

/* Runtime self-signed CA + server leaf (P-256, which satisfies the client
 * backend's security level).  Mirrors the socketpair harness generator. */
X509 *MkCert(EVP_PKEY *pubkey, EVP_PKEY *signkey, X509 *issuer, long serial,
             bool is_ca)
{
  X509           *x = X509_new();
  X509_NAME      *name;
  X509_EXTENSION *ext;
  X509V3_CTX      v3ctx;

  if (x == NULL) {
    return NULL;
  }
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
  X509_gmtime_adj(X509_getm_notBefore(x), -60);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60L);
  X509_set_pubkey(x, pubkey);
  /* Build the subject name in a fresh X509_NAME and install it with the
   * setter.  As of OpenSSL 4.0 X509_get_subject_name() returns const, because
   * the cert's internal name must not be mutated in place; the old pattern of
   * adding entries directly to it is invalid there. */
  name = X509_NAME_new();
  if (name == NULL) {
    X509_free(x);
    return NULL;
  }
  X509_NAME_add_entry_by_txt(
    name, "CN", MBSTRING_ASC,
    (const unsigned char *)(is_ca ? "c-ares test CA" : "c-ares test server"),
    -1, -1, 0);
  X509_set_subject_name(x, name);
  /* Self-signed certs use the subject as the issuer.  X509_set_issuer_name()
   * takes a const name and copies it, so the const getter is fine here. */
  X509_set_issuer_name(x,
                       issuer != NULL ? X509_get_subject_name(issuer) : name);
  X509_NAME_free(name);
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                            is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
  if (ext != NULL) {
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
  }
  /* The server leaf carries a subjectAltName so strict verification actually
   * checks the presented identity against the configured name. */
  if (!is_ca) {
    std::string san = std::string("DNS:") + kMockDoTHostname;
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, san.c_str());
    if (ext != NULL) {
      X509_add_ext(x, ext, -1);
      X509_EXTENSION_free(ext);
    }
  }
  if (!X509_sign(x, signkey, EVP_sha256())) {
    X509_free(x);
    return NULL;
  }
  return x;
}

class OpenSSLServerConn : public TlsServerConn {
public:
  explicit OpenSSLServerConn(SSL_CTX *ctx)
  {
    ssl_  = SSL_new(ctx);
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (ssl_ == NULL || rbio_ == NULL || wbio_ == NULL) {
      return;
    }
    /* An empty memory BIO must report "retry" rather than EOF, otherwise
     * SSL would treat an exhausted inbound buffer as a closed connection. */
    BIO_set_mem_eof_return(rbio_, -1);
    BIO_set_mem_eof_return(wbio_, -1);
    SSL_set_bio(ssl_, rbio_, wbio_); /* SSL takes ownership of both BIOs */
    SSL_set_accept_state(ssl_);
  }

  ~OpenSSLServerConn() override
  {
    if (ssl_ != NULL) {
      SSL_free(ssl_); /* also frees rbio_/wbio_ */
    }
  }

  void FeedCipher(const unsigned char *data, size_t len) override
  {
    if (len > 0 && rbio_ != NULL) {
      BIO_write(rbio_, data, (int)len);
    }
  }

  std::vector<unsigned char> DrainCipher() override
  {
    std::vector<unsigned char> out;
    unsigned char              buf[4096];
    int                        n;
    if (wbio_ == NULL) {
      return out;
    }
    while ((n = BIO_read(wbio_, buf, (int)sizeof(buf))) > 0) {
      out.insert(out.end(), buf, buf + n);
    }
    return out;
  }

  bool Handshake(bool *fatal) override
  {
    int rv;
    int err;
    *fatal = false;
    if (ssl_ == NULL) {
      *fatal = true;
      return false;
    }
    rv = SSL_do_handshake(ssl_);
    if (rv == 1) {
      established_ = true;
      return true;
    }
    err = SSL_get_error(ssl_, rv);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      return false;
    }
    *fatal = true;
    return false;
  }

  bool Established() const override
  {
    return established_;
  }

  bool ReadPlain(std::vector<unsigned char> *out, bool *closed) override
  {
    unsigned char buf[4096];
    *closed = false;
    if (ssl_ == NULL) {
      return false;
    }
    for (;;) {
      int n = SSL_read(ssl_, buf, (int)sizeof(buf));
      if (n > 0) {
        out->insert(out->end(), buf, buf + n);
        continue;
      }
      int err = SSL_get_error(ssl_, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return true;
      }
      if (err == SSL_ERROR_ZERO_RETURN) {
        *closed = true;
        return true;
      }
      return false;
    }
  }

  bool WritePlain(const unsigned char *data, size_t len) override
  {
    size_t off = 0;
    if (ssl_ == NULL) {
      return false;
    }
    while (off < len) {
      int n = SSL_write(ssl_, data + off, (int)(len - off));
      if (n <= 0) {
        return false;
      }
      off += (size_t)n;
    }
    return true;
  }

  bool WasResumed() override
  {
    if (ssl_ == nullptr) {
      return false;
    }
    return SSL_session_reused(ssl_) == 1;
  }

private:
  SSL *ssl_         = nullptr;
  BIO *rbio_        = nullptr;
  BIO *wbio_        = nullptr;
  bool established_ = false;
};

class OpenSSLServerCtx : public TlsServerCtx {
public:
  ~OpenSSLServerCtx() override
  {
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
    }
    if (srv_cert_ != nullptr) {
      X509_free(srv_cert_);
    }
    if (ca_cert_ != nullptr) {
      X509_free(ca_cert_);
    }
    if (srv_key_ != nullptr) {
      EVP_PKEY_free(srv_key_);
    }
    if (ca_key_ != nullptr) {
      EVP_PKEY_free(ca_key_);
    }
  }

  bool Init()
  {
    BIO  *bio;
    char *pem = nullptr;
    long  len;

    ca_key_  = EVP_EC_gen("P-256");
    srv_key_ = EVP_EC_gen("P-256");
    if (ca_key_ == nullptr || srv_key_ == nullptr) {
      return false;
    }
    ca_cert_ = MkCert(ca_key_, ca_key_, NULL, 1, true);
    if (ca_cert_ == nullptr) {
      return false;
    }
    srv_cert_ = MkCert(srv_key_, ca_key_, ca_cert_, 2, false);
    if (srv_cert_ == nullptr) {
      return false;
    }

    ctx_ = SSL_CTX_new(TLS_server_method());
    if (ctx_ == nullptr) {
      return false;
    }
    if (SSL_CTX_use_certificate(ctx_, srv_cert_) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, srv_key_) != 1) {
      return false;
    }
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

    /* Capture the CA in PEM so the client can trust it */
    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr || !PEM_write_bio_X509(bio, ca_cert_)) {
      if (bio != nullptr) {
        BIO_free(bio);
      }
      return false;
    }
    len = BIO_get_mem_data(bio, &pem);
    ca_pem_.assign(pem, pem + len);
    BIO_free(bio);
    return true;
  }

  std::unique_ptr<TlsServerConn> NewConn() override
  {
    return std::unique_ptr<TlsServerConn>(new OpenSSLServerConn(ctx_));
  }

  std::string CaPEM() const override
  {
    return ca_pem_;
  }

private:
  EVP_PKEY   *ca_key_   = nullptr;
  EVP_PKEY   *srv_key_  = nullptr;
  X509       *ca_cert_  = nullptr;
  X509       *srv_cert_ = nullptr;
  SSL_CTX    *ctx_      = nullptr;
  std::string ca_pem_;
};

}  // namespace

std::unique_ptr<TlsServerCtx> TlsServerCtx::Create()
{
  std::unique_ptr<OpenSSLServerCtx> ctx(new OpenSSLServerCtx());
  if (!ctx->Init()) {
    return nullptr;
  }
  return std::unique_ptr<TlsServerCtx>(ctx.release());
}

}  // namespace test
}  // namespace ares

#  elif defined(CARES_CRYPTO_SCHANNEL)

/* ========================================================================= *
 * Windows Schannel server-side TLS backend (SSPI, buffer-in / buffer-out)
 * ========================================================================= */

#    ifndef SCHANNEL_USE_BLACKLISTS
#      define SCHANNEL_USE_BLACKLISTS
#    endif
#    ifndef SECURITY_WIN32
#      define SECURITY_WIN32
#    endif

#    include <windows.h>
#    include <winternl.h>
#    include <wincrypt.h>
#    include <security.h>
#    include <sspi.h>
#    include <schannel.h>

#    define ARES_SCHAN_ASC_FLAGS                          \
      (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |  \
       ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | \
       ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)

namespace ares {
namespace test {

namespace {

/* Base64/PEM-encode a DER certificate (BEGIN/END CERTIFICATE headers). */
std::string DerToPem(const unsigned char *der, size_t len)
{
  DWORD       slen = 0;
  std::string out;
  if (!CryptBinaryToStringA(der, (DWORD)len, CRYPT_STRING_BASE64HEADER, NULL,
                            &slen)) {
    return out;
  }
  out.resize(slen);
  if (!CryptBinaryToStringA(der, (DWORD)len, CRYPT_STRING_BASE64HEADER, &out[0],
                            &slen)) {
    out.clear();
    return out;
  }
  out.resize(slen);
  return out;
}

/* Self-signed server certificate with an associated private key so Schannel
 * can present it to the client. */
PCCERT_CONTEXT MakeSelfSignedCert()
{
  BYTE                name_buf[256];
  CERT_NAME_BLOB      subject;
  CERT_ALT_NAME_ENTRY alt_entry;
  CERT_ALT_NAME_INFO  alt_info;
  CERT_EXTENSION      ext;
  CERT_EXTENSIONS     exts;
  BYTE               *alt_enc = NULL;
  DWORD               alt_len = 0;
  PCCERT_CONTEXT      cert;
  /* Wide form of kMockDoTHostname for the subjectAltName */
  static const WCHAR  kSanW[] = L"dot.example.com";

  subject.pbData = name_buf;
  subject.cbData = sizeof(name_buf);
  if (!CertStrToNameA(X509_ASN_ENCODING, "CN=c-ares test server",
                      CERT_X500_NAME_STR, NULL, name_buf, &subject.cbData,
                      NULL)) {
    return NULL;
  }

  /* subjectAltName = DNS:dot.example.com, so strict verification against a
   * configured authentication name is actually exercised. */
  memset(&alt_entry, 0, sizeof(alt_entry));
  alt_entry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
  alt_entry.pwszDNSName     = (LPWSTR)kSanW;
  alt_info.cAltEntry        = 1;
  alt_info.rgAltEntry       = &alt_entry;
  if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2,
                           &alt_info, CRYPT_ENCODE_ALLOC_FLAG, NULL, &alt_enc,
                           &alt_len)) {
    return NULL;
  }
  memset(&ext, 0, sizeof(ext));
  ext.pszObjId     = (LPSTR)szOID_SUBJECT_ALT_NAME2;
  ext.fCritical    = FALSE;
  ext.Value.cbData = alt_len;
  ext.Value.pbData = alt_enc;
  exts.cExtension  = 1;
  exts.rgExtension = &ext;

  /* NULL key handle + NULL key-prov-info: create/persist a key and associate
   * it with the cert so the Schannel server credential can use it. */
  cert =
    CertCreateSelfSignCertificate((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)NULL,
                                  &subject, 0, NULL, NULL, NULL, NULL, &exts);
  LocalFree(alt_enc);
  return cert;
}

class SchannelServerConn : public TlsServerConn {
public:
  explicit SchannelServerConn(CredHandle *cred) : cred_(cred)
  {
  }

  ~SchannelServerConn() override
  {
    if (have_ctxt_) {
      DeleteSecurityContext(&ctxt_);
    }
  }

  void FeedCipher(const unsigned char *data, size_t len) override
  {
    enc_in_.insert(enc_in_.end(), data, data + len);
  }

  std::vector<unsigned char> DrainCipher() override
  {
    std::vector<unsigned char> out;
    out.swap(enc_out_);
    return out;
  }

  bool Established() const override
  {
    return established_;
  }

  bool Handshake(bool *fatal) override
  {
    return AcceptLoop(fatal, false);
  }

  bool ReadPlain(std::vector<unsigned char> *out, bool *closed) override
  {
    *closed = false;
    for (;;) {
      SecBuffer       bufs[4];
      SecBufferDesc   desc;
      SECURITY_STATUS ss;
      SecBuffer      *data  = NULL;
      SecBuffer      *extra = NULL;
      int             i;

      if (enc_in_.empty()) {
        return true;
      }

      bufs[0].BufferType = SECBUFFER_DATA;
      bufs[0].pvBuffer   = enc_in_.data();
      bufs[0].cbBuffer   = (unsigned long)enc_in_.size();
      for (i = 1; i < 4; i++) {
        bufs[i].BufferType = SECBUFFER_EMPTY;
        bufs[i].pvBuffer   = NULL;
        bufs[i].cbBuffer   = 0;
      }
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers  = 4;
      desc.pBuffers  = bufs;

      ss = DecryptMessage(&ctxt_, &desc, 0, NULL);

      if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        return true; /* need more ciphertext from the socket */
      }
      if (ss == SEC_I_CONTEXT_EXPIRED) {
        *closed = true;
        return true;
      }
      if (ss == SEC_I_RENEGOTIATE) {
        if (!HandleRenegotiate(bufs)) {
          return false;
        }
        continue;
      }
      if (ss != SEC_E_OK) {
        return false;
      }

      for (i = 1; i < 4; i++) {
        if (bufs[i].BufferType == SECBUFFER_DATA && data == NULL) {
          data = &bufs[i];
        } else if (bufs[i].BufferType == SECBUFFER_EXTRA && extra == NULL) {
          extra = &bufs[i];
        }
      }

      if (data != NULL && data->cbBuffer > 0) {
        const unsigned char *p = (const unsigned char *)data->pvBuffer;
        out->insert(out->end(), p, p + data->cbBuffer);
      }

      KeepExtra(extra);
    }
  }

  bool WritePlain(const unsigned char *data, size_t len) override
  {
    size_t off = 0;
    if (!have_sizes_) {
      return false;
    }
    while (off < len) {
      size_t                     chunk = len - off;
      std::vector<unsigned char> buf;
      SecBuffer                  bufs[4];
      SecBufferDesc              desc;
      SECURITY_STATUS            ss;
      size_t                     total;

      if (chunk > sizes_.cbMaximumMessage) {
        chunk = sizes_.cbMaximumMessage;
      }
      buf.resize(sizes_.cbHeader + chunk + sizes_.cbTrailer);
      memcpy(buf.data() + sizes_.cbHeader, data + off, chunk);

      bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
      bufs[0].pvBuffer   = buf.data();
      bufs[0].cbBuffer   = sizes_.cbHeader;
      bufs[1].BufferType = SECBUFFER_DATA;
      bufs[1].pvBuffer   = buf.data() + sizes_.cbHeader;
      bufs[1].cbBuffer   = (unsigned long)chunk;
      bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
      bufs[2].pvBuffer   = buf.data() + sizes_.cbHeader + chunk;
      bufs[2].cbBuffer   = sizes_.cbTrailer;
      bufs[3].BufferType = SECBUFFER_EMPTY;
      bufs[3].pvBuffer   = NULL;
      bufs[3].cbBuffer   = 0;
      desc.ulVersion     = SECBUFFER_VERSION;
      desc.cBuffers      = 4;
      desc.pBuffers      = bufs;

      ss = EncryptMessage(&ctxt_, 0, &desc, 0);
      if (ss != SEC_E_OK) {
        return false;
      }
      total = (size_t)bufs[0].cbBuffer + (size_t)bufs[1].cbBuffer +
              (size_t)bufs[2].cbBuffer;
      enc_out_.insert(enc_out_.end(), buf.data(), buf.data() + total);
      off += chunk;
    }
    return true;
  }

  bool WasResumed() override
  {
    SecPkgContext_SessionInfo info;
    memset(&info, 0, sizeof(info));
    if (QueryContextAttributes(&ctxt_, SECPKG_ATTR_SESSION_INFO, &info) !=
        SEC_E_OK) {
      return false;
    }
    return (info.dwFlags & SSL_SESSION_RECONNECT) != 0;
  }

private:
  /* Keep only the SECBUFFER_EXTRA tail in enc_in_.  Its pvBuffer points inside
   * enc_in_, so copy it out before overwriting. */
  void KeepExtra(SecBuffer *extra)
  {
    if (extra != NULL && extra->cbBuffer > 0) {
      std::vector<unsigned char> tmp((const unsigned char *)extra->pvBuffer,
                                     (const unsigned char *)extra->pvBuffer +
                                       extra->cbBuffer);
      enc_in_.swap(tmp);
    } else {
      enc_in_.clear();
    }
  }

  /* DecryptMessage reported SEC_I_RENEGOTIATE: the handshake records are in
   * the SECBUFFER_EXTRA; feed them back through AcceptSecurityContext. */
  bool HandleRenegotiate(SecBuffer *bufs)
  {
    SecBuffer *extra = NULL;
    bool       fatal = false;
    int        i;
    for (i = 1; i < 4; i++) {
      if (bufs[i].BufferType == SECBUFFER_EXTRA) {
        extra = &bufs[i];
        break;
      }
    }
    KeepExtra(extra);
    AcceptLoop(&fatal, true);
    return !fatal;
  }

  /* Run AcceptSecurityContext over enc_in_, queuing output tokens into
   * enc_out_.  Returns true when the (re)negotiation reaches SEC_E_OK.  On the
   * initial handshake, records the stream sizes and marks established. */
  bool AcceptLoop(bool *fatal, bool reneg)
  {
    *fatal = false;
    for (;;) {
      SecBuffer       inbuf[2];
      SecBuffer       outbuf[1];
      SecBufferDesc   indesc;
      SecBufferDesc   outdesc;
      SECURITY_STATUS ss;
      ULONG           ret_flags = 0;
      TimeStamp       ts;

      inbuf[0].BufferType = SECBUFFER_TOKEN;
      inbuf[0].pvBuffer   = enc_in_.data();
      inbuf[0].cbBuffer   = (unsigned long)enc_in_.size();
      inbuf[1].BufferType = SECBUFFER_EMPTY;
      inbuf[1].pvBuffer   = NULL;
      inbuf[1].cbBuffer   = 0;
      indesc.ulVersion    = SECBUFFER_VERSION;
      indesc.cBuffers     = 2;
      indesc.pBuffers     = inbuf;

      outbuf[0].BufferType = SECBUFFER_TOKEN;
      outbuf[0].pvBuffer   = NULL;
      outbuf[0].cbBuffer   = 0;
      outdesc.ulVersion    = SECBUFFER_VERSION;
      outdesc.cBuffers     = 1;
      outdesc.pBuffers     = outbuf;

      ss = AcceptSecurityContext(cred_, have_ctxt_ ? &ctxt_ : NULL, &indesc,
                                 ARES_SCHAN_ASC_FLAGS, 0, &ctxt_, &outdesc,
                                 &ret_flags, &ts);
      have_ctxt_ = true;

      if (outbuf[0].cbBuffer != 0 && outbuf[0].pvBuffer != NULL) {
        const unsigned char *p = (const unsigned char *)outbuf[0].pvBuffer;
        enc_out_.insert(enc_out_.end(), p, p + outbuf[0].cbBuffer);
        FreeContextBuffer(outbuf[0].pvBuffer);
      }

      if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        return false; /* need more input; keep enc_in_ intact */
      }

      if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
        if (inbuf[1].BufferType == SECBUFFER_EXTRA) {
          size_t extra = inbuf[1].cbBuffer;
          enc_in_.erase(enc_in_.begin(),
                        enc_in_.begin() + (enc_in_.size() - extra));
        } else {
          enc_in_.clear();
        }

        if (ss == SEC_E_OK) {
          if (!reneg) {
            QueryContextAttributes(&ctxt_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
            have_sizes_  = true;
            established_ = true;
          }
          return true;
        }
        /* CONTINUE: keep going if more input is buffered, else wait */
        if (enc_in_.empty()) {
          return false;
        }
        continue;
      }

      *fatal = true;
      return false;
    }
  }

  CredHandle                *cred_;
  CtxtHandle                 ctxt_;
  bool                       have_ctxt_   = false;
  bool                       established_ = false;
  bool                       have_sizes_  = false;
  SecPkgContext_StreamSizes  sizes_;
  std::vector<unsigned char> enc_in_;
  std::vector<unsigned char> enc_out_;
};

class SchannelServerCtx : public TlsServerCtx {
public:
  ~SchannelServerCtx() override
  {
    if (have_cred_) {
      FreeCredentialsHandle(&cred_);
    }
    if (cert_ != NULL) {
      CertFreeCertificateContext(cert_);
    }
  }

  bool Init()
  {
    SCH_CREDENTIALS creds;
    SECURITY_STATUS ss;
    TimeStamp       ts;

    cert_ = MakeSelfSignedCert();
    if (cert_ == NULL) {
      return false;
    }

    memset(&creds, 0, sizeof(creds));
    creds.dwVersion = SCH_CREDENTIALS_VERSION;
    creds.cCreds    = 1;
    creds.paCred    = &cert_;
    creds.dwFlags   = SCH_USE_STRONG_CRYPTO;

    ss = AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A,
                                   SECPKG_CRED_INBOUND, NULL, &creds, NULL,
                                   NULL, &cred_, &ts);
    if (ss != SEC_E_OK) {
      return false;
    }
    have_cred_ = true;

    ca_pem_ = DerToPem(cert_->pbCertEncoded, cert_->cbCertEncoded);
    return !ca_pem_.empty();
  }

  std::unique_ptr<TlsServerConn> NewConn() override
  {
    return std::unique_ptr<TlsServerConn>(new SchannelServerConn(&cred_));
  }

  std::string CaPEM() const override
  {
    return ca_pem_;
  }

private:
  CredHandle     cred_;
  bool           have_cred_ = false;
  PCCERT_CONTEXT cert_      = nullptr;
  std::string    ca_pem_;
};

}  // namespace

std::unique_ptr<TlsServerCtx> TlsServerCtx::Create()
{
  std::unique_ptr<SchannelServerCtx> ctx(new SchannelServerCtx());
  if (!ctx->Init()) {
    return nullptr;
  }
  return std::unique_ptr<TlsServerCtx>(ctx.release());
}

}  // namespace test
}  // namespace ares

#  else  /* no server-side TLS termination for the compiled-in backend */

/* Provide a null factory so the mock DoT tests link and skip gracefully. */
namespace ares {
namespace test {

std::unique_ptr<TlsServerCtx> TlsServerCtx::Create()
{
  return nullptr;
}

}  // namespace test
}  // namespace ares

#  endif /* CARES_CRYPTO_OPENSSL / CARES_CRYPTO_SCHANNEL */

#endif   /* CARES_USE_CRYPTO */
