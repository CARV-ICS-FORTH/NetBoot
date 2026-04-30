/*
 * SHA-512 streaming implementation from the FIPS 180-4 specification.
 *
 * The sha512_compress() function implements the standard SHA-512 compression
 * function (FIPS 180-4 §6.4).  It is not derived from any copyrighted source;
 * the algorithm is a NIST standard.
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <crypto.h>	/* sha512_ctx_t, sha512_init/update/final */

/* SHA-512 round constants (FIPS 180-4 §4.2.3) */
static const uint64_t K[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_compress(sha512_ctx_t *ctx)
{
	uint64_t W[80];
	int i;

	for (i = 0; i < 16; i++)
		W[i] = ctx->input[i];
	for (; i < 80; i++) {
		uint64_t s0 = ROTR64(W[i-15], 1) ^ ROTR64(W[i-15], 8) ^ (W[i-15] >> 7);
		uint64_t s1 = ROTR64(W[i-2], 19) ^ ROTR64(W[i-2], 61) ^ (W[i-2] >> 6);
		W[i] = W[i-16] + s0 + W[i-7] + s1;
	}

	uint64_t a = ctx->hash[0], b = ctx->hash[1], c = ctx->hash[2], d = ctx->hash[3];
	uint64_t e = ctx->hash[4], f = ctx->hash[5], g = ctx->hash[6], h = ctx->hash[7];

	for (i = 0; i < 80; i++) {
		uint64_t S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
		uint64_t ch = (e & f) ^ (~e & g);
		uint64_t t1 = h + S1 + ch + K[i] + W[i];
		uint64_t S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
		uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
		uint64_t t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->hash[0] += a; ctx->hash[1] += b; ctx->hash[2] += c; ctx->hash[3] += d;
	ctx->hash[4] += e; ctx->hash[5] += f; ctx->hash[6] += g; ctx->hash[7] += h;
}

static uint64_t load_be64(const uint8_t *s)
{
	return ((uint64_t)s[0] << 56) | ((uint64_t)s[1] << 48) |
	       ((uint64_t)s[2] << 40) | ((uint64_t)s[3] << 32) |
	       ((uint64_t)s[4] << 24) | ((uint64_t)s[5] << 16) |
	       ((uint64_t)s[6] <<  8) |  (uint64_t)s[7];
}

static void store_be64(uint8_t *s, uint64_t v)
{
	s[0] = (uint8_t)(v >> 56); s[1] = (uint8_t)(v >> 48);
	s[2] = (uint8_t)(v >> 40); s[3] = (uint8_t)(v >> 32);
	s[4] = (uint8_t)(v >> 24); s[5] = (uint8_t)(v >> 16);
	s[6] = (uint8_t)(v >>  8); s[7] = (uint8_t)(v);
}

/* Load a complete 128-byte block from the byte-view of ctx->input into words */
static void load_block(sha512_ctx_t *ctx)
{
	uint8_t *buf = (uint8_t *)ctx->input;
	for (int i = 0; i < 16; i++)
		ctx->input[i] = load_be64(buf + i * 8);
}

void sha512_init(sha512_ctx_t *ctx)
{
	ctx->hash[0] = 0x6a09e667f3bcc908; ctx->hash[1] = 0xbb67ae8584caa73b;
	ctx->hash[2] = 0x3c6ef372fe94f82b; ctx->hash[3] = 0xa54ff53a5f1d36f1;
	ctx->hash[4] = 0x510e527fade682d1; ctx->hash[5] = 0x9b05688c2b3e6c1f;
	ctx->hash[6] = 0x1f83d9abfb41bd6b; ctx->hash[7] = 0x5be0cd19137e2179;
	ctx->input_size[0] = 0;
	ctx->input_size[1] = 0;
	ctx->input_idx = 0;
	memset(ctx->input, 0, sizeof(ctx->input));
}

void sha512_update(sha512_ctx_t *ctx, const uint8_t *msg, size_t len)
{
	/* ctx->input is used as a raw byte buffer until compress time */
	uint8_t *buf = (uint8_t *)ctx->input;

	while (len > 0) {
		size_t avail = 128 - ctx->input_idx;
		size_t n = (len < avail) ? len : avail;
		memcpy(buf + ctx->input_idx, msg, n);
		ctx->input_idx += n;
		msg += n;
		len -= n;

		if (ctx->input_idx == 128) {
			load_block(ctx);
			ctx->input_size[1] += 1024;
			if (ctx->input_size[1] < 1024)
				ctx->input_size[0]++;
			sha512_compress(ctx);
			ctx->input_idx = 0;
			memset(ctx->input, 0, sizeof(ctx->input));
		}
	}
}

void sha512_final(sha512_ctx_t *ctx, uint8_t hash[64])
{
	uint8_t *buf = (uint8_t *)ctx->input;

	/* Total bit count = accumulated (input_size) + partial block */
	uint64_t old_lo = ctx->input_size[1];
	uint64_t bits_lo = old_lo + (uint64_t)ctx->input_idx * 8;
	uint64_t bits_hi = ctx->input_size[0] + (bits_lo < old_lo ? 1 : 0);

	/* Append 0x80 padding byte */
	buf[ctx->input_idx++] = 0x80;
	memset(buf + ctx->input_idx, 0, 128 - ctx->input_idx);

	/* If no room for the 16-byte length field, flush this block first */
	if (ctx->input_idx > 112) {
		load_block(ctx);
		sha512_compress(ctx);
		memset(buf, 0, 128);
	}

	/* Append 128-bit big-endian message length at bytes 112..127 */
	store_be64(buf + 112, bits_hi);
	store_be64(buf + 120, bits_lo);

	load_block(ctx);
	sha512_compress(ctx);

	/* Output big-endian hash */
	for (int i = 0; i < 8; i++)
		store_be64(hash + i * 8, ctx->hash[i]);

	/* Wipe sensitive state */
	volatile uint8_t *p = (uint8_t *)ctx;
	for (size_t i = 0; i < sizeof(*ctx); i++)
		p[i] = 0;
}
