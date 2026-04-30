/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/**********\
* SHA-512  *
\**********/

/*
 * Streaming SHA-512 context.  The field layout is part of the ABI between
 * this header and src/crypto/sha512.c — do not reorder.
 */
typedef struct {
	uint64_t hash[8];
	uint64_t input[16];
	uint64_t input_size[2];
	size_t   input_idx;
} sha512_ctx_t;

void sha512_init  (sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const uint8_t *msg, size_t len);
void sha512_final (sha512_ctx_t *ctx, uint8_t hash[64]);

/*********************\
* Abstract crypto API *
\*********************/

/*
 * Algorithm identifiers — must match the GBL_FLAG_* values in img.h so that
 * imgp->global_hdr.flags can be cast directly to crypto_algo_t.
 */
typedef enum {
	CRYPTO_ALGO_NONE     = 0,
	CRYPTO_ALGO_ED25519  = 1,
	CRYPTO_ALGO_ECDSA384 = 2,
} crypto_algo_t;

/* Maximum sizes across all supported algorithms. */
#define CRYPTO_MAX_PUBKEY_SIZE  96	/* ECDSA384 key */
#define CRYPTO_MAX_SIG_SIZE     96	/* ECDSA384 sig */

/*
 * Opaque crypto context.  The concrete layout is private to each backend.
 */
typedef struct crypto_ctx crypto_ctx_t;

/*
 * Allocate and initialise a crypto context for the given algorithm.
 * Returns NULL if the algorithm is unsupported or allocation fails.
 */
crypto_ctx_t *crypto_init(crypto_algo_t algo);

/* Release all resources held by ctx. */
void crypto_exit(crypto_ctx_t *ctx);

/*
 * Stream public-key bytes into the context.  Safe to call in multiple
 * 8-byte increments as TFTP data arrives.
 * Returns 0 on success, -1 if more bytes are fed than the key size.
 */
int crypto_set_pubkey(crypto_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * Stream signature bytes into the context.  Same calling convention as
 * crypto_set_pubkey.
 */
int crypto_set_signature(crypto_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * One-shot signature verification over a two-part message:
 *
 *   hdr      — the 8-byte header (global_hdr.raw or cur_part_hdr.raw),
 *               passed by value so it lands in a register.
 *   body     — remainder of the message (decompressed payload or pubkey);
 *               may be NULL when body_len == 0.
 *   body_len — length of body in bytes.
 *
 * The backend feeds SHA-512(R || A || hdr_bytes || body) and checks the
 * EdDSA equation.  The stored signature is cleared on return so the context
 * can be reused for the next partition.
 *
 * Returns 0 on success, -1 on verification failure.
 */
int crypto_verify_signature(crypto_ctx_t *ctx, uint64_t hdr,
                             const void *body, size_t body_len);

/*
 * Built-in self-tests: SHA-512 KAT (FIPS 180-4) and an Ed25519
 * known-answer test (RFC 8032 §5.1 Test Vector 1 via the crypto API).
 * Returns 0 if all pass, -1 on the first failure.
 */
int crypto_selftest(void);

#endif /* _CRYPTO_H */
