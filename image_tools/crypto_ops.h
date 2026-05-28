/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Internal crypto operations API.
 *
 * cops_init selects the appropriate backend (file or HSM) based on the
 * path/URI, opens it, and caches the public key.  All signing goes
 * through cops_sign; all verification through cops_verify (which is
 * purely local and does not use the backend vtable).
 */
#ifndef _CRYPTO_OPS_H
#define _CRYPTO_OPS_H

#include <stdint.h>
#include <stddef.h>
#include <crypto.h>

/* Opaque context returned by cops_init */
struct cops_ctx;

/*
 * Initialise a crypto context.  path_or_uri selects the backend:
 *   "pkcs11:…" → HSM (future), anything else → encrypted PKCS#8 PEM file.
 * flags: 0 or KEYP_OPEN_FORCE_NEW (defined in keyp_backend.h, re-exported
 * here for callers that need it).
 */
#define COPS_KEY_NEW	(1 << 0)	/* generate fresh key even if one exists */

struct cops_ctx *cops_init(const char *path_or_uri, int flags);

/* Retrieve the cached public key (written into the container header). */
int    cops_get_pubkey(const struct cops_ctx *ctx, uint8_t *out, size_t *len);

/* Algorithm and size helpers. */
crypto_algo_t cops_algo(const struct cops_ctx *ctx);
size_t        cops_sig_size(const struct cops_ctx *ctx);
size_t        cops_pub_size(const struct cops_ctx *ctx);

/* Sign msg[0..msglen-1]; write sig_out (cops_sig_size() bytes). */
int    cops_sign(struct cops_ctx *ctx,
		 const uint8_t *msg, size_t msglen, uint8_t *sig_out);

/*
 * Local dual verification (builtin + OpenSSL cross-check).
 * Message is: hdr_raw (8 bytes) || body[0..body_len-1].
 * Does not use the backend vtable; safe to call without cops_init.
 */
int    cops_verify(crypto_algo_t algo,
		   const uint8_t *pub, size_t pub_len,
		   const uint8_t *sig, size_t sig_len,
		   uint64_t hdr_raw,
		   const void *body, size_t body_len);

void   cops_exit(struct cops_ctx *ctx);

/* Size queries by algorithm, for callers that need them before cops_init. */
static inline size_t
cops_pubkey_size_for_algo(crypto_algo_t algo)
{
	switch (algo) {
	case CRYPTO_ALGO_ED25519:  return 32;
	case CRYPTO_ALGO_ECDSA384: return 96;
	default:                   return 0;
	}
}

static inline size_t
cops_sig_size_for_algo(crypto_algo_t algo)
{
	switch (algo) {
	case CRYPTO_ALGO_ED25519:  return 64;
	case CRYPTO_ALGO_ECDSA384: return 96;
	default:                   return 0;
	}
}

#endif /* _CRYPTO_OPS_H */
