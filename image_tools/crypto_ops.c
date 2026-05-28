/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Crypto orchestration layer.
 *
 * cops_init selects and initialises a backend (currently always the file
 * backend; HSM support is added by including key_hsm.h and extending the
 * URI dispatch below).
 *
 * cops_verify is purely local: builtin + OpenSSL cross-check.  It does not
 * touch the backend vtable and can be called without a cops_ctx.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <crypto.h>
#include <utils.h>
#include "keyp_backend.h"
#include "key_file.h"
#include "crypto_ops.h"


/***********\
* cops_ctx  *
\***********/

struct cops_ctx {
	struct keyp_ops    *ops;
	crypto_algo_t       algo;
	const uint8_t      *pub;	/* points into backend's kf_ctx.pub */
	size_t              pub_len;
};


/***********\
* Public API *
\***********/

struct cops_ctx *
cops_init(const char *path_or_uri, int flags)
{
	struct cops_ctx *ctx = NULL;
	struct keyp_ops *ops = NULL;
	int kflags = (flags & COPS_KEY_NEW) ? KEYP_OPEN_FORCE_NEW : 0;

	/* Backend selection — extend here when key_hsm.c is added */
	ops = keyp_file_backend(path_or_uri);
	if (!ops)
		return NULL;

	ctx = malloc(sizeof(struct cops_ctx));
	if (!ctx)
		goto fail;
	memset(ctx, 0, sizeof(struct cops_ctx));
	ctx->ops  = ops;
	ctx->algo = ops->algo;

	if (ops->keyp_open(ops, kflags) < 0)
		goto fail;

	ctx->pub = ops->keyp_get_pubkey(ops);
	if (!ctx->pub)
		goto fail;
	ctx->pub_len = cops_pubkey_size_for_algo(ops->algo);
	if (ctx->pub_len == 0)
		goto fail;

	return ctx;

fail:
	if (ops) {
		ops->keyp_close(ops);
		free(ops);
	}
	free(ctx);
	return NULL;
}

int
cops_get_pubkey(const struct cops_ctx *ctx, uint8_t *out, size_t *len)
{
	if (!ctx || ctx->pub_len == 0 || *len < ctx->pub_len)
		return -1;
	memcpy(out, ctx->pub, ctx->pub_len);
	*len = ctx->pub_len;
	return 0;
}

crypto_algo_t
cops_algo(const struct cops_ctx *ctx)
{
	return ctx ? ctx->algo : (crypto_algo_t)0;
}

size_t
cops_sig_size(const struct cops_ctx *ctx)
{
	return ctx ? cops_sig_size_for_algo(ctx->algo) : 0;
}

size_t
cops_pub_size(const struct cops_ctx *ctx)
{
	return ctx ? cops_pubkey_size_for_algo(ctx->algo) : 0;
}

int
cops_sign(struct cops_ctx *ctx,
	  const uint8_t *msg, size_t msglen, uint8_t *sig_out)
{
	if (!ctx || !ctx->ops || !ctx->ops->keyp_sign)
		return -1;
	return ctx->ops->keyp_sign(ctx->ops, msg, msglen, sig_out);
}

int
cops_verify(crypto_algo_t algo,
	    const uint8_t *pub, size_t pub_len,
	    const uint8_t *sig, size_t sig_len,
	    uint64_t hdr_raw,
	    const void *body, size_t body_len)
{
	crypto_ctx_t *bctx = NULL;
	EVP_PKEY     *evp_key = NULL;
	EVP_MD_CTX   *mdctx = NULL;
	uint8_t      *msg = NULL;
	size_t        msg_len = 0;
	int           builtin_ok = 0, openssl_ok = 0;

	if (body_len > SIZE_MAX - sizeof(uint64_t)) {
		ERR("cops_verify: body_len overflow\n");
		return -1;
	}

	/* OpenSSL path below is hardcoded for Ed25519.  ECDSA384 will be
	 * added when Caliptra-based verification lands; until then, fail
	 * loudly rather than silently producing "openssl: FAIL". */
	if (algo != CRYPTO_ALGO_ED25519) {
		ERR("cops_verify: unsupported algorithm %d"
		    " (only ED25519 is implemented)\n", (int)algo);
		return -1;
	}

	/* Builtin verification */
	bctx = crypto_init(algo);
	if (bctx) {
		crypto_set_pubkey(bctx, pub, pub_len);
		crypto_set_signature(bctx, sig, sig_len);
		builtin_ok = (crypto_verify_signature(bctx, hdr_raw,
						      body, body_len) == 0);
		crypto_exit(bctx);
	}
	INF("  builtin : %s\n", builtin_ok ? "PASS" : "FAIL");

	/* OpenSSL verification — flat message: hdr_raw || body */
	msg_len = sizeof(uint64_t) + body_len;
	msg = malloc(msg_len);
	if (!msg)
		goto out;

	memcpy(msg, &hdr_raw, sizeof(uint64_t));
	if (body_len > 0 && body)
		memcpy(msg + sizeof(uint64_t), body, body_len);

	evp_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
					      pub, pub_len);
	if (evp_key) {
		mdctx = EVP_MD_CTX_new();
		if (mdctx) {
			if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL,
						 evp_key) == 1 &&
			    EVP_DigestVerify(mdctx, sig, sig_len,
					     msg, msg_len) == 1)
				openssl_ok = 1;
			EVP_MD_CTX_free(mdctx);
		}
		EVP_PKEY_free(evp_key);
	}
	free(msg);
	msg = NULL;

out:
	INF("  openssl : %s\n", openssl_ok ? "PASS" : "FAIL");

	if (builtin_ok != openssl_ok)
		WRN("cops_verify: implementations disagree!\n");

	return (builtin_ok && openssl_ok) ? 0 : -1;
}

void
cops_exit(struct cops_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->ops) {
		ctx->ops->keyp_close(ctx->ops);
		free(ctx->ops);
	}
	/* pub points into the backend's kf_ctx — zeroed by keyp_close above */
	free(ctx);
}
