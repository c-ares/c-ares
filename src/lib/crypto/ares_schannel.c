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

#include "ares_private.h"

#ifdef CARES_CRYPTO_SCHANNEL

/* SCHANNEL_USE_BLACKLISTS is required by recent Windows SDKs to expose the
 * modern SCH_CREDENTIALS structure (needed for TLS 1.3).  Define it before
 * including schannel.h. */
#  ifndef SCHANNEL_USE_BLACKLISTS
#    define SCHANNEL_USE_BLACKLISTS
#  endif
#  ifndef SECURITY_WIN32
#    define SECURITY_WIN32
#  endif

#  include <windows.h>
/* <winternl.h> provides UNICODE_STRING, which the modern schannel.h
 * CRYPTO_SETTINGS / TLS_PARAMETERS / SCH_CREDENTIALS structures reference;
 * without it schannel.h fails to parse on recent SDKs. */
#  include <winternl.h>
#  include <wincrypt.h>
#  include <security.h>
#  include <sspi.h>
#  include <schannel.h>

/* Flags for InitializeSecurityContext.  MANUAL_CRED_VALIDATION lets us run
 * our own chain/name verification so the default/strict/opportunistic modes
 * behave identically to the OpenSSL backend. */
#  define ARES_SCHAN_ISC_FLAGS                          \
    (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |  \
     ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | \
     ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |         \
     ISC_REQ_MANUAL_CRED_VALIDATION)

/* Cap a single socket read pulled into the inbound ciphertext buffer.  A TLS
 * record is at most ~16k + overhead; a comfortable single-read chunk. */
#  define ARES_SCHAN_READ_CHUNK 16384

struct ares_cryptoimp_ctx {
  CredHandle         cred;      /* Client credential handle */
  ares_bool_t        have_cred; /* Whether cred was acquired */
  HCERTSTORE         ca_store;  /* Custom CA store (set_cadata), or NULL */
  ares_crypto_ctx_t *parent;
};

struct ares_tls {
  ares_conn_t              *conn;
  ares_cryptoimp_ctx_t     *ctx;
  CtxtHandle                ctxt; /* Security context */
  ares_bool_t               have_ctxt;
  ares_tls_state_t          state;
  ares_tls_stateflag_t      flags;
  ares_conn_err_t           last_io_error;
  ares_tls_verify_t         verify;      /* Resolved verification mode */
  char                     *target_name; /* SNI / verification name, or NULL */

  SecPkgContext_StreamSizes sizes;
  ares_bool_t               have_sizes;

  ares_bool_t hs_complete; /* ISC returned SEC_E_OK; only flush remains */
  ares_bool_t
    in_post_handshake;     /* Draining a post-handshake (renegotiate) flight */
  ares_bool_t    use_supplied_creds; /* Continue anonymously after the server
                                      * requested a client cert we don't have */

  /* Inbound ciphertext read from the socket, not yet consumed by Schannel.
   * Valid bytes are [0, enc_in_len). */
  unsigned char *enc_in;
  size_t         enc_in_len;
  size_t         enc_in_alloc;

  /* Outbound ciphertext to write to the socket.  Valid bytes are
   * [enc_out_off, enc_out_len); enc_out_off tracks partial socket writes. */
  unsigned char *enc_out;
  size_t         enc_out_len;
  size_t         enc_out_off;
  size_t         enc_out_alloc;

  /* Decrypted plaintext ready to hand to the caller.  Valid bytes are
   * [dec_in_off, dec_in_len). */
  unsigned char *dec_in;
  size_t         dec_in_len;
  size_t         dec_in_off;
  size_t         dec_in_alloc;
};

/* ------------------------------------------------------------------------- *
 * Byte-buffer helpers
 *
 * The inbound (enc_in), outbound (enc_out) and decrypted (dec_in) staging
 * buffers are hand-managed rather than ares_buf_t on purpose.  SSPI's
 * DecryptMessage() decrypts the inbound record *in place* and hands back
 * SecBuffer pointers into that same memory -- the decrypted SECBUFFER_DATA and
 * the still-unconsumed SECBUFFER_EXTRA suffix.  That requires mutable access to
 * the raw buffered bytes, which ares_buf deliberately does not expose:
 * ares_buf_peek() returns a read-only pointer, and mutating an ares_buf's
 * internal storage behind its back would violate its invariants.  So these
 * three buffers use a plain append + consume-from-front model; the growth
 * below is overflow-guarded.
 * ------------------------------------------------------------------------- */

static ares_bool_t schan_buf_append(unsigned char **buf, size_t *len,
                                    size_t *alloc, const unsigned char *data,
                                    size_t datalen)
{
  size_t need;

  if (datalen == 0) {
    return ARES_TRUE;
  }
  /* Overflow-safe growth.  In practice these buffers are bounded by ~16 KB
   * TLS records, but guard the size arithmetic anyway. */
  if (datalen > (size_t)-1 - *len) {
    return ARES_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  need = *len + datalen;
  if (need > *alloc) {
    size_t         newalloc = (*alloc == 0) ? 4096 : *alloc;
    unsigned char *newbuf;
    while (newalloc < need) {
      if (newalloc > ((size_t)-1) / 2) {
        newalloc = need; /* can't double without overflow; use exact size */
        break;
      }
      newalloc *= 2;
    }
    newbuf = ares_realloc(*buf, newalloc);
    if (newbuf == NULL) {
      return ARES_FALSE; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    *buf   = newbuf;
    *alloc = newalloc;
  }
  memcpy(*buf + *len, data, datalen);
  *len += datalen;
  return ARES_TRUE;
}

/* Write as much pending outbound ciphertext to the socket as possible.
 * Returns SUCCESS when fully drained, WOULDBLOCK when the socket can't take
 * more right now, or a transport error. */
static ares_conn_err_t schan_flush(ares_tls_t *tls)
{
  while (tls->enc_out_off < tls->enc_out_len) {
    size_t          wrote = 0;
    ares_conn_err_t err =
      ares_conn_write_raw(tls->conn, tls->enc_out + tls->enc_out_off,
                          tls->enc_out_len - tls->enc_out_off, &wrote);
    if (err != ARES_CONN_ERR_SUCCESS) {
      /* WOULDBLOCK is normal flow control, not a failure to remember */
      if (err != ARES_CONN_ERR_WOULDBLOCK) {
        tls->last_io_error = err;
      }
      return err;
    }
    if (wrote == 0) {
      /* Socket accepted nothing without signaling wouldblock; treat as
       * wouldblock to avoid spinning */
      return ARES_CONN_ERR_WOULDBLOCK; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    tls->enc_out_off += wrote;
  }
  tls->enc_out_len = 0;
  tls->enc_out_off = 0;
  return ARES_CONN_ERR_SUCCESS;
}

/* Pull more inbound ciphertext from the socket into enc_in.  Returns SUCCESS
 * if any bytes were read, WOULDBLOCK if none available, CONNCLOSED on EOF, or
 * a transport error. */
static ares_conn_err_t schan_fill(ares_tls_t *tls)
{
  unsigned char   tmp[ARES_SCHAN_READ_CHUNK];
  size_t          got = 0;
  ares_conn_err_t err = ares_conn_read_raw(tls->conn, tmp, sizeof(tmp), &got);
  if (err != ARES_CONN_ERR_SUCCESS) {
    if (err != ARES_CONN_ERR_WOULDBLOCK) {
      tls->last_io_error = err;
    }
    return err;
  }
  if (got == 0) {
    return ARES_CONN_ERR_WOULDBLOCK;
  }
  if (!schan_buf_append(&tls->enc_in, &tls->enc_in_len, &tls->enc_in_alloc, tmp,
                        got)) {
    return ARES_CONN_ERR_NOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  return ARES_CONN_ERR_SUCCESS;
}

/* Keep only the trailing `extra` bytes of enc_in (the unconsumed remainder
 * SSPI reported via a SECBUFFER_EXTRA). */
static void schan_enc_in_keep_tail(ares_tls_t *tls, size_t extra)
{
  if (extra == 0 || extra >= tls->enc_in_len) {
    if (extra == 0) {
      tls->enc_in_len = 0;
    }
    return;
  }
  memmove(tls->enc_in, tls->enc_in + (tls->enc_in_len - extra), extra);
  tls->enc_in_len = extra;
}

static ares_conn_err_t schan_map_error(ares_tls_t *tls, SECURITY_STATUS ss)
{
  switch (ss) {
    case SEC_E_UNTRUSTED_ROOT:
    case SEC_E_CERT_EXPIRED:
    case SEC_E_WRONG_PRINCIPAL:
    case SEC_E_CERT_UNKNOWN:
    case SEC_E_ILLEGAL_MESSAGE:
    case SEC_E_ALGORITHM_MISMATCH:
    case SEC_E_UNSUPPORTED_FUNCTION:
    case SEC_E_NO_CREDENTIALS:
    /* Tampered / undecryptable records and bad tokens are security failures,
     * not retriable transport errors. */
    case SEC_E_MESSAGE_ALTERED:
    case SEC_E_DECRYPT_FAILURE:
    case SEC_E_INVALID_TOKEN:
      return ARES_CONN_ERR_SECURITY;
    case SEC_E_INSUFFICIENT_MEMORY:
      return ARES_CONN_ERR_NOMEM;
    default:
      break;
  }
  /* last_io_error only holds a genuine transport failure -- WOULDBLOCK is not
   * stored there (see schan_flush/schan_fill) -- so fall back to it, else a
   * generic reset. */
  if (tls->last_io_error != ARES_CONN_ERR_SUCCESS) {
    return tls->last_io_error;
  }
  return ARES_CONN_ERR_CONNRESET;
}

/* ------------------------------------------------------------------------- *
 * Context (credential) lifecycle
 * ------------------------------------------------------------------------- */

static ares_status_t schan_acquire_cred(ares_cryptoimp_ctx_t *ctx)
{
  SECURITY_STATUS ss;
  TimeStamp       expiry;
#  ifdef SCH_CREDENTIALS_VERSION
  SCH_CREDENTIALS creds;
  TLS_PARAMETERS  tls_params;

  memset(&creds, 0, sizeof(creds));
  memset(&tls_params, 0, sizeof(tls_params));
  creds.dwVersion = SCH_CREDENTIALS_VERSION;
  /* Manual validation so we control default/strict/opportunistic; no default
   * client cert (mTLS is a follow-up); strong crypto only. */
  creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS |
                  SCH_USE_STRONG_CRYPTO;
  /* Pin a TLS 1.2 minimum (RFC 8310 / BCP 195): SCH_USE_STRONG_CRYPTO only
   * restricts ciphers, not protocol versions, so on a host policy that still
   * enables TLS 1.0/1.1 a DoT connection could otherwise negotiate below 1.2.
   * Disable everything below 1.2; 1.3 (and any future version) stays enabled,
   * matching the OpenSSL backend's SSL_CTX_set_min_proto_version(TLS1_2). */
  tls_params.grbitDisabledProtocols =
    (DWORD)(SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_TLS1_0_CLIENT |
            SP_PROT_TLS1_1_CLIENT);
  creds.cTlsParameters = 1;
  creds.pTlsParameters = &tls_params;
#  else
  SCHANNEL_CRED creds;

  memset(&creds, 0, sizeof(creds));
  creds.dwVersion = SCHANNEL_CRED_VERSION;
  creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS |
                  SCH_USE_STRONG_CRYPTO;
  /* Legacy path (no TLS 1.3 support in this SDK): allowlist TLS 1.2 to enforce
   * the same 1.2 minimum as the modern path above. */
  creds.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
#  endif

  ss = AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A,
                                 SECPKG_CRED_OUTBOUND, NULL, &creds, NULL, NULL,
                                 &ctx->cred, &expiry);
  if (ss != SEC_E_OK) {
    return ss == SEC_E_INSUFFICIENT_MEMORY ? ARES_ENOMEM : ARES_ESERVFAIL;
  }
  ctx->have_cred = ARES_TRUE;
  return ARES_SUCCESS;
}

ares_status_t ares_cryptoimp_ctx_init(ares_cryptoimp_ctx_t **ctx,
                                      ares_crypto_ctx_t     *parent)
{
  ares_status_t status;

  *ctx = ares_malloc_zero(sizeof(**ctx));
  if (*ctx == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  (*ctx)->parent = parent;

  status = schan_acquire_cred(*ctx);
  if (status != ARES_SUCCESS) {
    ares_cryptoimp_ctx_destroy(*ctx);
    *ctx = NULL;
    return status;
  }

  return ARES_SUCCESS;
}

void ares_cryptoimp_ctx_destroy(ares_cryptoimp_ctx_t *ctx)
{
  if (ctx == NULL) {
    return;
  }
  if (ctx->have_cred) {
    FreeCredentialsHandle(&ctx->cred);
  }
  if (ctx->ca_store != NULL) {
    CertCloseStore(ctx->ca_store, 0);
  }
  ares_free(ctx);
}

void ares_cryptoimp_thread_cleanup(ares_cryptoimp_ctx_t *ctx)
{
  /* Schannel keeps no per-thread state of ours to release */
  (void)ctx;
}

ares_status_t ares_tlsimp_set_cadata(ares_cryptoimp_ctx_t *ctx,
                                     const unsigned char *pem, size_t len)
{
  /* Custom CA is provided as PEM; convert each certificate to DER and add it
   * to an in-memory store consulted (as the exclusive trust anchor) during
   * chain validation. */
  static const char    begin_marker[] = "-----BEGIN CERTIFICATE-----";
  static const char    end_marker[]   = "-----END CERTIFICATE-----";
  size_t               count          = 0;
  const unsigned char *p;
  const unsigned char *end;

  if (ctx == NULL || pem == NULL || len == 0) {
    return ARES_EFORMERR;
  }

  if (ctx->ca_store == NULL) {
    ctx->ca_store =
      CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (HCRYPTPROV_LEGACY)0, 0, NULL);
    if (ctx->ca_store == NULL) {
      return ARES_ESERVFAIL; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  p   = pem;
  end = p + len;
  while (p < end) {
    const unsigned char *b;
    const unsigned char *e;
    DWORD                derlen = 0;
    unsigned char       *der;

    b = ares_memmem(p, (size_t)(end - p), (const unsigned char *)begin_marker,
                    sizeof(begin_marker) - 1);
    if (b == NULL) {
      break;
    }
    e = ares_memmem(b, (size_t)(end - b), (const unsigned char *)end_marker,
                    sizeof(end_marker) - 1);
    if (e == NULL) {
      break;
    }
    e += sizeof(end_marker) - 1;

    /* Decode the whole PEM block (header+base64+footer) to DER */
    if (!CryptStringToBinaryA((LPCSTR)b, (DWORD)(e - b),
                              CRYPT_STRING_BASE64HEADER, NULL, &derlen, NULL,
                              NULL)) {
      p = e;
      continue;
    }
    if (derlen == 0) {
      /* Degenerate/empty block: nothing to add, don't ares_malloc(0) */
      p = e;
      continue;
    }
    der = ares_malloc(derlen);
    if (der == NULL) {
      break; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (CryptStringToBinaryA((LPCSTR)b, (DWORD)(e - b),
                             CRYPT_STRING_BASE64HEADER, der, &derlen, NULL,
                             NULL)) {
      if (CertAddEncodedCertificateToStore(
            ctx->ca_store, X509_ASN_ENCODING, der, derlen,
            CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        count++;
      }
    }
    ares_free(der);
    p = e;
  }

  if (count == 0) {
    return ARES_EBADSTR;
  }
  return ARES_SUCCESS;
}

/* ------------------------------------------------------------------------- *
 * Certificate verification
 * ------------------------------------------------------------------------- */

static ares_conn_err_t schan_verify_cert(ares_tls_t *tls)
{
  SECURITY_STATUS                  ss;
  PCCERT_CONTEXT                   cert   = NULL;
  PCCERT_CHAIN_CONTEXT             chain  = NULL;
  HCERTCHAINENGINE                 engine = NULL;
  CERT_CHAIN_PARA                  chainpara;
  CERT_CHAIN_POLICY_PARA           polpara;
  CERT_CHAIN_POLICY_STATUS         polstatus;
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslpara;
  LPWSTR                           wname = NULL;
  ares_conn_err_t                  rv    = ARES_CONN_ERR_SECURITY;
  LPCSTR                           usage = szOID_PKIX_KP_SERVER_AUTH;

  ss =
    QueryContextAttributes(&tls->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
  if (ss != SEC_E_OK || cert == NULL) {
    return ARES_CONN_ERR_SECURITY;
  }

  /* When a custom CA was supplied, build chains against it as the exclusive
   * trust anchor rather than the system store */
  if (tls->ctx->ca_store != NULL) {
    CERT_CHAIN_ENGINE_CONFIG cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cbSize         = sizeof(cfg);
    cfg.hExclusiveRoot = tls->ctx->ca_store;
    if (!CertCreateCertificateChainEngine(&cfg, &engine)) {
      /* Fail closed: falling back to the default (system) chain engine would
       * validate against all public CAs instead of the configured one. */
      engine = NULL;
      rv     = ARES_CONN_ERR_SECURITY;
      goto done;
    }
  }

  memset(&chainpara, 0, sizeof(chainpara));
  chainpara.cbSize                                    = sizeof(chainpara);
  chainpara.RequestedUsage.dwType                     = USAGE_MATCH_TYPE_AND;
  chainpara.RequestedUsage.Usage.cUsageIdentifier     = 1;
  chainpara.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR *)&usage;

  if (!CertGetCertificateChain(engine, cert, NULL, cert->hCertStore, &chainpara,
                               0, NULL, &chain)) {
    goto done;
  }

  if (tls->target_name != NULL && ares_strlen(tls->target_name) > 0) {
    /* Use CP_UTF8 (locale-independent) rather than CP_ACP: the authentication
     * name is an ASCII/punycode DNS hostname, so the ANSI code page would only
     * introduce locale-dependent behavior for non-ASCII input. */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, tls->target_name, -1, NULL, 0);
    if (wlen > 0) {
      wname = ares_malloc_zero_array((size_t)wlen, sizeof(WCHAR));
      if (wname != NULL) {
        MultiByteToWideChar(CP_UTF8, 0, tls->target_name, -1, wname, wlen);
      }
    }
    if (wname == NULL) {
      /* An authentication name was configured but couldn't be converted;
       * fail closed rather than silently skipping the name check (which a
       * NULL pwszServerName below would do). */
      rv = ARES_CONN_ERR_SECURITY;
      goto done;
    }
  }

  memset(&sslpara, 0, sizeof(sslpara));
  sslpara.cbSize         = sizeof(sslpara);
  sslpara.dwAuthType     = AUTHTYPE_SERVER;
  sslpara.pwszServerName = wname; /* NULL => skip name check (chain-only) */

  memset(&polpara, 0, sizeof(polpara));
  polpara.cbSize            = sizeof(polpara);
  polpara.pvExtraPolicyPara = &sslpara;

  memset(&polstatus, 0, sizeof(polstatus));
  polstatus.cbSize = sizeof(polstatus);

  if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &polpara,
                                        &polstatus)) {
    goto done;
  }

  if (polstatus.dwError != 0) {
    rv = ARES_CONN_ERR_SECURITY;
    goto done;
  }

  rv = ARES_CONN_ERR_SUCCESS;

done:
  ares_free(wname);
  if (chain != NULL) {
    CertFreeCertificateChain(chain);
  }
  if (engine != NULL) {
    CertFreeCertificateChainEngine(engine);
  }
  if (cert != NULL) {
    CertFreeCertificateContext(cert);
  }
  return rv;
}

static ares_conn_err_t schan_finish_handshake(ares_tls_t *tls)
{
  SECURITY_STATUS ss;

  ss =
    QueryContextAttributes(&tls->ctxt, SECPKG_ATTR_STREAM_SIZES, &tls->sizes);
  if (ss != SEC_E_OK) {
    tls->state = ARES_TLS_STATE_ERROR;
    return ARES_CONN_ERR_CONNRESET;
  }
  tls->have_sizes = ARES_TRUE;

  if (tls->verify != ARES_TLS_VERIFY_OPPORTUNISTIC) {
    ares_conn_err_t verr = schan_verify_cert(tls);
    if (verr != ARES_CONN_ERR_SUCCESS) {
      tls->state = ARES_TLS_STATE_ERROR;
      return verr;
    }
  }

  tls->state       = ARES_TLS_STATE_ESTABLISHED;
  tls->hs_complete = ARES_FALSE;
  return ARES_CONN_ERR_SUCCESS;
}

/* Re-validate the peer certificate after a post-handshake (SEC_I_RENEGOTIATE)
 * flight.  Harmless for TLS 1.3 (cert can't change; a NewSessionTicket uses
 * the same path), and closes the TLS 1.2 gap where a server-initiated
 * renegotiation could present a different, unchecked certificate. */
static ares_conn_err_t schan_reneg_revalidate(ares_tls_t *tls)
{
  ares_conn_err_t verr;
  if (tls->verify == ARES_TLS_VERIFY_OPPORTUNISTIC) {
    return ARES_CONN_ERR_SUCCESS;
  }
  verr = schan_verify_cert(tls);
  if (verr != ARES_CONN_ERR_SUCCESS) {
    tls->state = ARES_TLS_STATE_ERROR;
  }
  return verr;
}

/* Older SDKs (the legacy SCHANNEL_CRED path, TLS 1.2 only) don't define this. */
#  ifndef SP_PROT_TLS1_3_CLIENT
#    define SP_PROT_TLS1_3_CLIENT 0x00002000
#  endif

/* Whether a SEC_I_RENEGOTIATE is a genuine server-initiated renegotiation that
 * must be refused, as opposed to a TLS 1.3 post-handshake flight (which
 * Schannel also surfaces as SEC_I_RENEGOTIATE).  Returns TRUE only when the
 * negotiated protocol can be *positively* confirmed to be pre-TLS-1.3; if the
 * version query fails it returns FALSE so a real TLS 1.3 NewSessionTicket /
 * KeyUpdate is never mistakenly refused (the flight is instead processed and
 * the certificate re-validated defensively). */
static ares_bool_t schan_reneg_must_refuse(ares_tls_t *tls)
{
  SecPkgContext_ConnectionInfo ci;

  memset(&ci, 0, sizeof(ci));
  if (QueryContextAttributes(&tls->ctxt, SECPKG_ATTR_CONNECTION_INFO, &ci) !=
      SEC_E_OK) {
    return ARES_FALSE;
  }
  return (ci.dwProtocol & SP_PROT_TLS1_3_CLIENT) ? ARES_FALSE : ARES_TRUE;
}

/* ------------------------------------------------------------------------- *
 * Handshake driver
 * ------------------------------------------------------------------------- */

/* Drive the (initial or post-handshake) negotiation using non-blocking socket
 * I/O.  `post` is TRUE when processing a post-handshake flight triggered by
 * SEC_I_RENEGOTIATE from DecryptMessage: on completion it returns SUCCESS
 * without re-validating the certificate or changing the established state. */
static ares_conn_err_t schan_handshake(ares_tls_t *tls, ares_bool_t post)
{
  /* Set when ISC returned SEC_I_MESSAGE_FRAGMENT: the next iteration must
   * re-invoke ISC to emit the next output fragment without waiting to read
   * the server (which would otherwise deadlock on WANTREAD). */
  ares_bool_t producing = ARES_FALSE;

  /* If the final flight was produced but not yet fully flushed, just finish
   * flushing and complete. */
  if (tls->hs_complete) {
    ares_conn_err_t ferr = schan_flush(tls);
    if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
      tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
      return ferr;
    }
    if (ferr != ARES_CONN_ERR_SUCCESS) {
      return ferr;
    }
    if (post) {
      /* Post-handshake flight done (e.g. a TLS 1.3 NewSessionTicket); reset
       * so the next SEC_I_RENEGOTIATE isn't short-circuited by the guard. */
      tls->hs_complete = ARES_FALSE;
      return ARES_CONN_ERR_SUCCESS;
    }
    return schan_finish_handshake(tls);
  }

  for (;;) {
    SecBuffer       inbuf[2];
    SecBufferDesc   indesc;
    SecBuffer       outbuf[1];
    SecBufferDesc   outdesc;
    SECURITY_STATUS ss;
    unsigned long   ret_flags = 0;
    ares_bool_t     initial   = (tls->have_ctxt ? ARES_FALSE : ARES_TRUE);
    ares_conn_err_t ferr;
    ares_conn_err_t rerr;

    /* Flush any pending output before generating more */
    ferr = schan_flush(tls);
    if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
      tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
      return ferr;
    }
    if (ferr != ARES_CONN_ERR_SUCCESS) {
      return ferr;
    }

    /* Every non-initial step needs inbound data -- unless we're re-invoking
     * ISC only to emit a further output fragment (no server read). */
    if (!initial && !producing && tls->enc_in_len == 0) {
      rerr = schan_fill(tls);
      if (rerr == ARES_CONN_ERR_WOULDBLOCK) {
        tls->flags |= ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD;
        return rerr;
      }
      if (rerr != ARES_CONN_ERR_SUCCESS) {
        return rerr;
      }
    }

    if (!initial) {
      inbuf[0].BufferType = SECBUFFER_TOKEN;
      inbuf[0].pvBuffer   = tls->enc_in;
      inbuf[0].cbBuffer   = (unsigned long)tls->enc_in_len;
      inbuf[1].BufferType = SECBUFFER_EMPTY;
      inbuf[1].pvBuffer   = NULL;
      inbuf[1].cbBuffer   = 0;
      indesc.ulVersion    = SECBUFFER_VERSION;
      indesc.cBuffers     = 2;
      indesc.pBuffers     = inbuf;
    }

    outbuf[0].BufferType = SECBUFFER_TOKEN;
    outbuf[0].pvBuffer   = NULL;
    outbuf[0].cbBuffer   = 0;
    outdesc.ulVersion    = SECBUFFER_VERSION;
    outdesc.cBuffers     = 1;
    outdesc.pBuffers     = outbuf;

    ss = InitializeSecurityContextA(
      &tls->ctx->cred, initial ? NULL : &tls->ctxt,
      (SEC_CHAR *)tls->target_name,
      ARES_SCHAN_ISC_FLAGS |
        (tls->use_supplied_creds ? ISC_REQ_USE_SUPPLIED_CREDS : 0),
      0, 0, initial ? NULL : &indesc, 0, initial ? &tls->ctxt : NULL, &outdesc,
      &ret_flags, NULL);

    tls->have_ctxt = ARES_TRUE;

    /* Queue any produced handshake token */
    if (outbuf[0].cbBuffer != 0 && outbuf[0].pvBuffer != NULL) {
      ares_bool_t ok =
        schan_buf_append(&tls->enc_out, &tls->enc_out_len, &tls->enc_out_alloc,
                         outbuf[0].pvBuffer, outbuf[0].cbBuffer);
      FreeContextBuffer(outbuf[0].pvBuffer);
      if (!ok) {
        return ARES_CONN_ERR_NOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }

    if (ss == SEC_E_INCOMPLETE_MESSAGE) {
      /* Keep enc_in intact; need more ciphertext.  Flush anything queued
       * first, then read. */
      ferr = schan_flush(tls);
      if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
        tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
        return ferr;
      }
      if (ferr != ARES_CONN_ERR_SUCCESS) {
        return ferr;
      }
      rerr = schan_fill(tls);
      if (rerr == ARES_CONN_ERR_WOULDBLOCK) {
        tls->flags |= ARES_TLS_SF_READ_WANTREAD | ARES_TLS_SF_WRITE_WANTREAD;
        return rerr;
      }
      if (rerr != ARES_CONN_ERR_SUCCESS) {
        return rerr;
      }
      continue;
    }

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED ||
        ss == SEC_I_MESSAGE_FRAGMENT) {
      /* Consume input, preserving any SECBUFFER_EXTRA remainder */
      if (!initial) {
        if (inbuf[1].BufferType == SECBUFFER_EXTRA) {
          schan_enc_in_keep_tail(tls, (size_t)inbuf[1].cbBuffer);
        } else {
          tls->enc_in_len = 0;
        }
      }

      if (ss == SEC_E_OK) {
        tls->hs_complete = ARES_TRUE;
      }

      /* Flush the produced flight */
      ferr = schan_flush(tls);
      if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
        tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
        return ferr;
      }
      if (ferr != ARES_CONN_ERR_SUCCESS) {
        return ferr;
      }

      if (ss == SEC_E_OK) {
        if (post) {
          tls->hs_complete = ARES_FALSE;
          return ARES_CONN_ERR_SUCCESS;
        }
        return schan_finish_handshake(tls);
      }

      /* SEC_I_MESSAGE_FRAGMENT: the output token was fragmented -- loop to
       * re-invoke ISC and emit the next fragment without reading the server.
       * SEC_I_CONTINUE_NEEDED: read the server's next flight. */
      producing = (ss == SEC_I_MESSAGE_FRAGMENT) ? ARES_TRUE : ARES_FALSE;
      continue;
    }

    if (ss == SEC_I_INCOMPLETE_CREDENTIALS && !tls->use_supplied_creds) {
      /* The server sent a CertificateRequest but our credential carries no
       * client certificate (SCH_CRED_NO_DEFAULT_CREDS; mTLS is deferred).
       * Continue the handshake anonymously by re-invoking ISC with
       * ISC_REQ_USE_SUPPLIED_CREDS on the same server flight (enc_in is not
       * consumed here), matching mature Schannel clients.  A server that
       * merely *requests* -- rather than *requires* -- a client cert then
       * proceeds; if it recurs after we set the flag it falls through to the
       * fatal branch below rather than looping. */
      tls->use_supplied_creds = ARES_TRUE;
      producing               = ARES_TRUE; /* re-invoke; no server read */
      continue;
    }

    /* Any other status is fatal */
    tls->state = ARES_TLS_STATE_ERROR;
    return schan_map_error(tls, ss);
  }
}

/* ------------------------------------------------------------------------- *
 * Provider entry points
 * ------------------------------------------------------------------------- */

ares_status_t ares_tlsimp_create(ares_tls_t          **tls,
                                 ares_cryptoimp_ctx_t *crypto_ctx,
                                 ares_conn_t          *conn)
{
  ares_tls_t *state;

  if (tls == NULL || crypto_ctx == NULL || conn == NULL) {
    return ARES_EFORMERR;
  }

  state = ares_malloc_zero(sizeof(*state));
  if (state == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  state->conn  = conn;
  state->ctx   = crypto_ctx;
  state->state = ARES_TLS_STATE_INIT;

  if (ares_strlen(conn->server->tls_hostname) > 0) {
    state->target_name = ares_strdup(conn->server->tls_hostname);
    if (state->target_name == NULL) {
      ares_free(state);
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  /* Resolve the verification mode via the shared helper so it can't drift
   * from the session-cache key's folding (default is strict with a name,
   * opportunistic without, per RFC 8310). */
  state->verify = ares_tls_effective_verify(conn);

  *tls = state;
  return ARES_SUCCESS;
}

void ares_tlsimp_destroy(ares_tls_t *tls)
{
  if (tls == NULL) {
    return;
  }
  if (tls->have_ctxt) {
    DeleteSecurityContext(&tls->ctxt);
  }
  ares_free(tls->target_name);
  ares_free(tls->enc_in);
  ares_free(tls->enc_out);
  ares_free(tls->dec_in);
  ares_free(tls);
}

ares_conn_err_t ares_tlsimp_connect(ares_tls_t *tls)
{
  if (tls == NULL || (tls->state != ARES_TLS_STATE_INIT &&
                      tls->state != ARES_TLS_STATE_CONNECT)) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->state  = ARES_TLS_STATE_CONNECT;
  tls->flags &= ~((unsigned int)(ARES_TLS_SF_READ | ARES_TLS_SF_WRITE));

  return schan_handshake(tls, ARES_FALSE);
}

ares_conn_err_t ares_tlsimp_read(ares_tls_t *tls, unsigned char *buf,
                                 size_t *buf_len)
{
  size_t want;

  if (tls == NULL || tls->state != ARES_TLS_STATE_ESTABLISHED) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->flags &= ~((unsigned int)ARES_TLS_SF_READ);

  /* Resume any in-flight post-handshake negotiation before touching app
   * data */
  if (tls->in_post_handshake) {
    ares_conn_err_t herr = schan_handshake(tls, ARES_TRUE);
    if (herr == ARES_CONN_ERR_WOULDBLOCK) {
      return herr;
    }
    if (herr != ARES_CONN_ERR_SUCCESS) {
      return herr;
    }
    tls->in_post_handshake = ARES_FALSE;
    herr                   = schan_reneg_revalidate(tls);
    if (herr != ARES_CONN_ERR_SUCCESS) {
      return herr;
    }
  }

  /* Serve buffered plaintext first */
  if (tls->dec_in_off >= tls->dec_in_len) {
    /* Need to decrypt more */
    for (;;) {
      SecBuffer       bufs[4];
      SecBufferDesc   desc;
      SECURITY_STATUS ss;
      size_t          i;
      SecBuffer      *pdata  = NULL;
      SecBuffer      *pextra = NULL;
      ares_conn_err_t herr;

      if (tls->enc_in_len == 0) {
        ares_conn_err_t rerr = schan_fill(tls);
        if (rerr == ARES_CONN_ERR_WOULDBLOCK) {
          tls->flags |= ARES_TLS_SF_READ_WANTREAD;
          return rerr;
        }
        if (rerr == ARES_CONN_ERR_CONNCLOSED) {
          tls->state = ARES_TLS_STATE_DISCONNECTED;
          return ARES_CONN_ERR_CONNCLOSED;
        }
        if (rerr != ARES_CONN_ERR_SUCCESS) {
          return rerr;
        }
      }

      bufs[0].BufferType = SECBUFFER_DATA;
      bufs[0].pvBuffer   = tls->enc_in;
      bufs[0].cbBuffer   = (unsigned long)tls->enc_in_len;
      for (i = 1; i < 4; i++) {
        bufs[i].BufferType = SECBUFFER_EMPTY;
        bufs[i].pvBuffer   = NULL;
        bufs[i].cbBuffer   = 0;
      }
      desc.ulVersion = SECBUFFER_VERSION;
      desc.cBuffers  = 4;
      desc.pBuffers  = bufs;

      ss = DecryptMessage(&tls->ctxt, &desc, 0, NULL);

      if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        ares_conn_err_t rerr = schan_fill(tls);
        if (rerr == ARES_CONN_ERR_WOULDBLOCK) {
          tls->flags |= ARES_TLS_SF_READ_WANTREAD;
          return rerr;
        }
        if (rerr == ARES_CONN_ERR_CONNCLOSED) {
          tls->state = ARES_TLS_STATE_DISCONNECTED;
          return ARES_CONN_ERR_CONNCLOSED;
        }
        if (rerr != ARES_CONN_ERR_SUCCESS) {
          return rerr;
        }
        continue;
      }

      if (ss == SEC_I_CONTEXT_EXPIRED) {
        /* Peer sent close_notify */
        tls->state = ARES_TLS_STATE_DISCONNECTED;
        return ARES_CONN_ERR_CONNCLOSED;
      }

      if (ss == SEC_I_RENEGOTIATE) {
        /* Schannel surfaces both a TLS 1.3 post-handshake message
         * (NewSessionTicket / KeyUpdate) and a genuine pre-1.3
         * server-initiated renegotiation as SEC_I_RENEGOTIATE.  A DoT client
         * never needs renegotiation, and a TLS 1.2 renegotiation could present
         * a *different*, unvalidated certificate -- so refuse it fail-closed
         * when the protocol is positively pre-1.3.  A TLS 1.3 flight (or one
         * whose version can't be confirmed) is processed normally below (the
         * cert cannot change under 1.3) and re-validated defensively via
         * schan_reneg_revalidate(). */
        size_t extra = 0;
        if (schan_reneg_must_refuse(tls)) {
          tls->state = ARES_TLS_STATE_ERROR;
          return ARES_CONN_ERR_SECURITY;
        }
        for (i = 1; i < 4; i++) {
          if (bufs[i].BufferType == SECBUFFER_EXTRA) {
            extra = (size_t)bufs[i].cbBuffer;
            break;
          }
        }
        schan_enc_in_keep_tail(tls, extra);
        tls->in_post_handshake = ARES_TRUE;
        herr                   = schan_handshake(tls, ARES_TRUE);
        if (herr == ARES_CONN_ERR_WOULDBLOCK) {
          return herr;
        }
        if (herr != ARES_CONN_ERR_SUCCESS) {
          return herr;
        }
        tls->in_post_handshake = ARES_FALSE;
        herr                   = schan_reneg_revalidate(tls);
        if (herr != ARES_CONN_ERR_SUCCESS) {
          return herr;
        }
        continue;
      }

      if (ss != SEC_E_OK) {
        tls->state = ARES_TLS_STATE_ERROR;
        return schan_map_error(tls, ss);
      }

      /* Locate decrypted data and any leftover ciphertext */
      for (i = 1; i < 4; i++) {
        if (bufs[i].BufferType == SECBUFFER_DATA && pdata == NULL) {
          pdata = &bufs[i];
        } else if (bufs[i].BufferType == SECBUFFER_EXTRA && pextra == NULL) {
          pextra = &bufs[i];
        }
      }

      /* Copy plaintext out before we disturb enc_in (SECBUFFER_DATA and
       * SECBUFFER_EXTRA both point inside enc_in). */
      if (pdata != NULL && pdata->cbBuffer > 0) {
        tls->dec_in_off = 0;
        tls->dec_in_len = 0;
        if (!schan_buf_append(&tls->dec_in, &tls->dec_in_len,
                              &tls->dec_in_alloc,
                              (const unsigned char *)pdata->pvBuffer,
                              (size_t)pdata->cbBuffer)) {
          return ARES_CONN_ERR_NOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        }
      }

      if (pextra != NULL && pextra->cbBuffer > 0) {
        /* pextra->pvBuffer points within enc_in; move it to the front */
        memmove(tls->enc_in, pextra->pvBuffer, (size_t)pextra->cbBuffer);
        tls->enc_in_len = (size_t)pextra->cbBuffer;
      } else {
        tls->enc_in_len = 0;
      }

      if (tls->dec_in_len > tls->dec_in_off) {
        break; /* have plaintext to return */
      }
      /* Zero-length app record (e.g. a lone ticket already consumed); loop */
    }
  }

  want = tls->dec_in_len - tls->dec_in_off;
  if (want > *buf_len) {
    want = *buf_len;
  }
  memcpy(buf, tls->dec_in + tls->dec_in_off, want);
  tls->dec_in_off += want;
  if (tls->dec_in_off >= tls->dec_in_len) {
    tls->dec_in_off = 0;
    tls->dec_in_len = 0;
  }
  *buf_len = want;
  return ARES_CONN_ERR_SUCCESS;
}

ares_conn_err_t ares_tlsimp_write(ares_tls_t *tls, const unsigned char *buf,
                                  size_t *buf_len)
{
  size_t          consumed = 0;
  ares_conn_err_t ferr;

  if (tls == NULL || tls->state != ARES_TLS_STATE_ESTABLISHED ||
      !tls->have_sizes) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->flags &= ~((unsigned int)ARES_TLS_SF_WRITE);

  /* Flush any ciphertext left over from a prior partial write first */
  ferr = schan_flush(tls);
  if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
    tls->flags |= ARES_TLS_SF_WRITE_WANTWRITE;
    *buf_len    = 0;
    return ferr;
  }
  if (ferr != ARES_CONN_ERR_SUCCESS) {
    return ferr;
  }

  while (consumed < *buf_len) {
    size_t          chunk = *buf_len - consumed;
    size_t          total;
    unsigned char  *scratch;
    SecBuffer       bufs[4];
    SecBufferDesc   desc;
    SECURITY_STATUS ss;
    ares_bool_t     ok;

    if (chunk > tls->sizes.cbMaximumMessage) {
      chunk = tls->sizes.cbMaximumMessage;
    }

    scratch = ares_malloc(tls->sizes.cbHeader + chunk + tls->sizes.cbTrailer);
    if (scratch == NULL) {
      return ARES_CONN_ERR_NOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    memcpy(scratch + tls->sizes.cbHeader, buf + consumed, chunk);

    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer   = scratch;
    bufs[0].cbBuffer   = tls->sizes.cbHeader;
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer   = scratch + tls->sizes.cbHeader;
    bufs[1].cbBuffer   = (unsigned long)chunk;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer   = scratch + tls->sizes.cbHeader + chunk;
    bufs[2].cbBuffer   = tls->sizes.cbTrailer;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].pvBuffer   = NULL;
    bufs[3].cbBuffer   = 0;
    desc.ulVersion     = SECBUFFER_VERSION;
    desc.cBuffers      = 4;
    desc.pBuffers      = bufs;

    ss = EncryptMessage(&tls->ctxt, 0, &desc, 0);
    if (ss != SEC_E_OK) {
      ares_free(scratch);
      tls->state = ARES_TLS_STATE_ERROR;
      return schan_map_error(tls, ss);
    }

    /* Header, data and trailer are contiguous in scratch */
    total = (size_t)bufs[0].cbBuffer + (size_t)bufs[1].cbBuffer +
            (size_t)bufs[2].cbBuffer;
    ok = schan_buf_append(&tls->enc_out, &tls->enc_out_len, &tls->enc_out_alloc,
                          scratch, total);
    ares_free(scratch);
    if (!ok) {
      return ARES_CONN_ERR_NOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* We own enc_out and will keep flushing it, so the plaintext chunk is
     * consumed regardless of whether the flush fully drains now */
    consumed += chunk;

    ferr = schan_flush(tls);
    if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
      tls->flags |= ARES_TLS_SF_WRITE_WANTWRITE;
      *buf_len    = consumed;
      return ferr;
    }
    if (ferr != ARES_CONN_ERR_SUCCESS) {
      return ferr;
    }
  }

  *buf_len = consumed;
  return ARES_CONN_ERR_SUCCESS;
}

ares_conn_err_t ares_tlsimp_shutdown(ares_tls_t *tls)
{
  SecBuffer       inbuf[1];
  SecBufferDesc   indesc;
  SecBuffer       outbuf[1];
  SecBufferDesc   outdesc;
  SECURITY_STATUS ss;
  unsigned long   ret_flags = 0;
  DWORD           token     = SCHANNEL_SHUTDOWN;
  ares_conn_err_t ferr;

  if (tls == NULL || (tls->state != ARES_TLS_STATE_ESTABLISHED &&
                      tls->state != ARES_TLS_STATE_SHUTDOWN)) {
    return ARES_CONN_ERR_INVALID;
  }

  tls->state  = ARES_TLS_STATE_SHUTDOWN;
  tls->flags &= ~((unsigned int)(ARES_TLS_SF_READ | ARES_TLS_SF_WRITE));

  /* If we still owe the close_notify bytes from a prior call, just flush */
  if (tls->enc_out_len > tls->enc_out_off) {
    ferr = schan_flush(tls);
    if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
      tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
      return ferr;
    }
    tls->state = ARES_TLS_STATE_DISCONNECTED;
    return ARES_CONN_ERR_SUCCESS;
  }

  inbuf[0].BufferType = SECBUFFER_TOKEN;
  inbuf[0].pvBuffer   = &token;
  inbuf[0].cbBuffer   = sizeof(token);
  indesc.ulVersion    = SECBUFFER_VERSION;
  indesc.cBuffers     = 1;
  indesc.pBuffers     = inbuf;

  if (ApplyControlToken(&tls->ctxt, &indesc) != SEC_E_OK) {
    tls->state = ARES_TLS_STATE_DISCONNECTED;
    return ARES_CONN_ERR_SUCCESS;
  }

  outbuf[0].BufferType = SECBUFFER_TOKEN;
  outbuf[0].pvBuffer   = NULL;
  outbuf[0].cbBuffer   = 0;
  outdesc.ulVersion    = SECBUFFER_VERSION;
  outdesc.cBuffers     = 1;
  outdesc.pBuffers     = outbuf;

  ss = InitializeSecurityContextA(
    &tls->ctx->cred, &tls->ctxt, (SEC_CHAR *)tls->target_name,
    ARES_SCHAN_ISC_FLAGS, 0, 0, NULL, 0, NULL, &outdesc, &ret_flags, NULL);

  if (outbuf[0].cbBuffer != 0 && outbuf[0].pvBuffer != NULL) {
    schan_buf_append(&tls->enc_out, &tls->enc_out_len, &tls->enc_out_alloc,
                     outbuf[0].pvBuffer, outbuf[0].cbBuffer);
    FreeContextBuffer(outbuf[0].pvBuffer);
  }

  (void)ss;

  ferr = schan_flush(tls);
  if (ferr == ARES_CONN_ERR_WOULDBLOCK) {
    tls->flags |= ARES_TLS_SF_READ_WANTWRITE | ARES_TLS_SF_WRITE_WANTWRITE;
    return ferr;
  }

  tls->state = ARES_TLS_STATE_DISCONNECTED;
  return ARES_CONN_ERR_SUCCESS;
}

ares_bool_t ares_tlsimp_get_read_pending(ares_tls_t *tls)
{
  if (tls == NULL) {
    return ARES_FALSE;
  }
  if (tls->dec_in_len > tls->dec_in_off) {
    return ARES_TRUE;
  }
  if (tls->enc_in_len > 0) {
    return ARES_TRUE;
  }
  if (tls->in_post_handshake) {
    return ARES_TRUE;
  }
  return ARES_FALSE;
}

/* --- Early data (0-RTT) ---------------------------------------------------
 * Schannel does not support TLS 1.3 early data (0-RTT): it exposes no
 * client-side early-data write primitive.  Microsoft's own MsQuic
 * documentation calls this out and directs callers that need 0-RTT to
 * OpenSSL.  Reporting a zero early-data size makes the connection layer skip
 * early data entirely and perform an ordinary 1-RTT handshake (see
 * ares_conn_write()); 0-RTT is available only with the OpenSSL backend. */

size_t ares_tlsimp_get_earlydata_size(ares_tls_t *tls)
{
  (void)tls;
  return 0;
}

ares_conn_err_t ares_tlsimp_earlydata_write(ares_tls_t          *tls,
                                            const unsigned char *buf,
                                            size_t              *buf_len)
{
  (void)tls;
  (void)buf;
  (void)buf_len;
  return ARES_CONN_ERR_NOTIMP;
}

ares_bool_t ares_tlsimp_earlydata_accepted(ares_tls_t *tls)
{
  (void)tls;
  return ARES_FALSE;
}

ares_tls_state_t ares_tlsimp_get_state(ares_tls_t *tls)
{
  if (tls == NULL) {
    /* Fail safe: a NULL handle must not be treated as a fresh INIT state that
     * the connection layer would route into a connect attempt. */
    return ARES_TLS_STATE_ERROR;
  }
  return tls->state;
}

ares_tls_stateflag_t ares_tlsimp_get_stateflag(ares_tls_t *tls)
{
  if (tls == NULL) {
    return 0;
  }
  return tls->flags;
}

void ares_tlsimp_session_free(void *arg)
{
  /* Schannel manages session resumption internally via the credential
   * handle; the generic session cache is unused by this backend */
  (void)arg;
}

#endif /* CARES_CRYPTO_SCHANNEL */
