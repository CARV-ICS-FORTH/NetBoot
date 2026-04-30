/*
 * Ed25519 signature verification — public domain ref10 implementation.
 *
 * Field arithmetic and group operations from SUPERCOP ref10:
 *   D.J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang,
 *   "High-speed high-security signatures", CHES 2011.
 *   https://github.com/jedisct1/supercop/tree/master/crypto_sign/ed25519/ref10
 *   Public domain.
 *
 * Scalar reduction (sc_reduce) from the same ref10 distribution.
 *
 * Only the verification path is present; key generation and signing are
 * intentionally omitted so the bootloader surface stays minimal.
 *
 * Adaptation SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * Adaptation SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <crypto.h>	/* sha512_ctx_t, sha512_*, crypto_ctx_t, crypto_* */
#include <utils.h>	/* For console output */

/* ref10 type aliases */
typedef int32_t  crypto_int32;
typedef int64_t  crypto_int64;
typedef uint32_t crypto_uint32;
typedef uint64_t crypto_uint64;

typedef uint8_t  u8;
typedef uint64_t u64;

/* bit i of scalar a[], used by slide() */
#define crypto_int8_bitmod_01(a, i) (((a) >> ((i) & 7)) & 1)

static crypto_uint64 load_3(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  return result;
}

static crypto_uint64 load_4(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  result |= ((crypto_uint64) in[3]) << 24;
  return result;
}

/***********************************************\
*  GF(2^255-19) field element — 10-limb radix  *
\***********************************************/

typedef crypto_int32 fe[10];

static const fe d = {
	-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116
};
static const fe sqrtm1 = {
	-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482
};
static const fe d2 = {
	-21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199
};

static void fe_0(fe h)
{
	h[0]=0; h[1]=0; h[2]=0; h[3]=0; h[4]=0;
	h[5]=0; h[6]=0; h[7]=0; h[8]=0; h[9]=0;
}

static void fe_1(fe h)
{
	h[0]=1; h[1]=0; h[2]=0; h[3]=0; h[4]=0;
	h[5]=0; h[6]=0; h[7]=0; h[8]=0; h[9]=0;
}

void fe_copy(fe h,const fe f)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  h[0] = f0;
  h[1] = f1;
  h[2] = f2;
  h[3] = f3;
  h[4] = f4;
  h[5] = f5;
  h[6] = f6;
  h[7] = f7;
  h[8] = f8;
  h[9] = f9;
}

/*
h = -f

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
*/

void fe_neg(fe h,const fe f)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 h0 = -f0;
  crypto_int32 h1 = -f1;
  crypto_int32 h2 = -f2;
  crypto_int32 h3 = -f3;
  crypto_int32 h4 = -f4;
  crypto_int32 h5 = -f5;
  crypto_int32 h6 = -f6;
  crypto_int32 h7 = -f7;
  crypto_int32 h8 = -f8;
  crypto_int32 h9 = -f9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
h = f + g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

void fe_add(fe h,const fe f,const fe g)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 g0 = g[0];
  crypto_int32 g1 = g[1];
  crypto_int32 g2 = g[2];
  crypto_int32 g3 = g[3];
  crypto_int32 g4 = g[4];
  crypto_int32 g5 = g[5];
  crypto_int32 g6 = g[6];
  crypto_int32 g7 = g[7];
  crypto_int32 g8 = g[8];
  crypto_int32 g9 = g[9];
  crypto_int32 h0 = f0 + g0;
  crypto_int32 h1 = f1 + g1;
  crypto_int32 h2 = f2 + g2;
  crypto_int32 h3 = f3 + g3;
  crypto_int32 h4 = f4 + g4;
  crypto_int32 h5 = f5 + g5;
  crypto_int32 h6 = f6 + g6;
  crypto_int32 h7 = f7 + g7;
  crypto_int32 h8 = f8 + g8;
  crypto_int32 h9 = f9 + g9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
h = f - g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

void fe_sub(fe h,const fe f,const fe g)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 g0 = g[0];
  crypto_int32 g1 = g[1];
  crypto_int32 g2 = g[2];
  crypto_int32 g3 = g[3];
  crypto_int32 g4 = g[4];
  crypto_int32 g5 = g[5];
  crypto_int32 g6 = g[6];
  crypto_int32 g7 = g[7];
  crypto_int32 g8 = g[8];
  crypto_int32 g9 = g[9];
  crypto_int32 h0 = f0 - g0;
  crypto_int32 h1 = f1 - g1;
  crypto_int32 h2 = f2 - g2;
  crypto_int32 h3 = f3 - g3;
  crypto_int32 h4 = f4 - g4;
  crypto_int32 h5 = f5 - g5;
  crypto_int32 h6 = f6 - g6;
  crypto_int32 h7 = f7 - g7;
  crypto_int32 h8 = f8 - g8;
  crypto_int32 h9 = f9 - g9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
h = f * g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
Notes on implementation strategy:

Using schoolbook multiplication.
Karatsuba would save a little in some cost models.

Most multiplications by 2 and 19 are 32-bit precomputations;
cheaper than 64-bit postcomputations.

There is one remaining multiplication by 19 in the carry chain;
one *19 precomputation can be merged into this,
but the resulting data flow is considerably less clean.

There are 12 carries below.
10 of them are 2-way parallelizable and vectorizable.
Can get away with 11 carries, but then data flow is much deeper.

With tighter constraints on inputs can squeeze carries into int32.
*/

void fe_mul(fe h,const fe f,const fe g)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 g0 = g[0];
  crypto_int32 g1 = g[1];
  crypto_int32 g2 = g[2];
  crypto_int32 g3 = g[3];
  crypto_int32 g4 = g[4];
  crypto_int32 g5 = g[5];
  crypto_int32 g6 = g[6];
  crypto_int32 g7 = g[7];
  crypto_int32 g8 = g[8];
  crypto_int32 g9 = g[9];
  crypto_int32 g1_19 = 19 * g1; /* 1.959375*2^29 */
  crypto_int32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
  crypto_int32 g3_19 = 19 * g3;
  crypto_int32 g4_19 = 19 * g4;
  crypto_int32 g5_19 = 19 * g5;
  crypto_int32 g6_19 = 19 * g6;
  crypto_int32 g7_19 = 19 * g7;
  crypto_int32 g8_19 = 19 * g8;
  crypto_int32 g9_19 = 19 * g9;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f9_2 = 2 * f9;
  crypto_int64 f0g0    = f0   * (crypto_int64) g0;
  crypto_int64 f0g1    = f0   * (crypto_int64) g1;
  crypto_int64 f0g2    = f0   * (crypto_int64) g2;
  crypto_int64 f0g3    = f0   * (crypto_int64) g3;
  crypto_int64 f0g4    = f0   * (crypto_int64) g4;
  crypto_int64 f0g5    = f0   * (crypto_int64) g5;
  crypto_int64 f0g6    = f0   * (crypto_int64) g6;
  crypto_int64 f0g7    = f0   * (crypto_int64) g7;
  crypto_int64 f0g8    = f0   * (crypto_int64) g8;
  crypto_int64 f0g9    = f0   * (crypto_int64) g9;
  crypto_int64 f1g0    = f1   * (crypto_int64) g0;
  crypto_int64 f1g1_2  = f1_2 * (crypto_int64) g1;
  crypto_int64 f1g2    = f1   * (crypto_int64) g2;
  crypto_int64 f1g3_2  = f1_2 * (crypto_int64) g3;
  crypto_int64 f1g4    = f1   * (crypto_int64) g4;
  crypto_int64 f1g5_2  = f1_2 * (crypto_int64) g5;
  crypto_int64 f1g6    = f1   * (crypto_int64) g6;
  crypto_int64 f1g7_2  = f1_2 * (crypto_int64) g7;
  crypto_int64 f1g8    = f1   * (crypto_int64) g8;
  crypto_int64 f1g9_38 = f1_2 * (crypto_int64) g9_19;
  crypto_int64 f2g0    = f2   * (crypto_int64) g0;
  crypto_int64 f2g1    = f2   * (crypto_int64) g1;
  crypto_int64 f2g2    = f2   * (crypto_int64) g2;
  crypto_int64 f2g3    = f2   * (crypto_int64) g3;
  crypto_int64 f2g4    = f2   * (crypto_int64) g4;
  crypto_int64 f2g5    = f2   * (crypto_int64) g5;
  crypto_int64 f2g6    = f2   * (crypto_int64) g6;
  crypto_int64 f2g7    = f2   * (crypto_int64) g7;
  crypto_int64 f2g8_19 = f2   * (crypto_int64) g8_19;
  crypto_int64 f2g9_19 = f2   * (crypto_int64) g9_19;
  crypto_int64 f3g0    = f3   * (crypto_int64) g0;
  crypto_int64 f3g1_2  = f3_2 * (crypto_int64) g1;
  crypto_int64 f3g2    = f3   * (crypto_int64) g2;
  crypto_int64 f3g3_2  = f3_2 * (crypto_int64) g3;
  crypto_int64 f3g4    = f3   * (crypto_int64) g4;
  crypto_int64 f3g5_2  = f3_2 * (crypto_int64) g5;
  crypto_int64 f3g6    = f3   * (crypto_int64) g6;
  crypto_int64 f3g7_38 = f3_2 * (crypto_int64) g7_19;
  crypto_int64 f3g8_19 = f3   * (crypto_int64) g8_19;
  crypto_int64 f3g9_38 = f3_2 * (crypto_int64) g9_19;
  crypto_int64 f4g0    = f4   * (crypto_int64) g0;
  crypto_int64 f4g1    = f4   * (crypto_int64) g1;
  crypto_int64 f4g2    = f4   * (crypto_int64) g2;
  crypto_int64 f4g3    = f4   * (crypto_int64) g3;
  crypto_int64 f4g4    = f4   * (crypto_int64) g4;
  crypto_int64 f4g5    = f4   * (crypto_int64) g5;
  crypto_int64 f4g6_19 = f4   * (crypto_int64) g6_19;
  crypto_int64 f4g7_19 = f4   * (crypto_int64) g7_19;
  crypto_int64 f4g8_19 = f4   * (crypto_int64) g8_19;
  crypto_int64 f4g9_19 = f4   * (crypto_int64) g9_19;
  crypto_int64 f5g0    = f5   * (crypto_int64) g0;
  crypto_int64 f5g1_2  = f5_2 * (crypto_int64) g1;
  crypto_int64 f5g2    = f5   * (crypto_int64) g2;
  crypto_int64 f5g3_2  = f5_2 * (crypto_int64) g3;
  crypto_int64 f5g4    = f5   * (crypto_int64) g4;
  crypto_int64 f5g5_38 = f5_2 * (crypto_int64) g5_19;
  crypto_int64 f5g6_19 = f5   * (crypto_int64) g6_19;
  crypto_int64 f5g7_38 = f5_2 * (crypto_int64) g7_19;
  crypto_int64 f5g8_19 = f5   * (crypto_int64) g8_19;
  crypto_int64 f5g9_38 = f5_2 * (crypto_int64) g9_19;
  crypto_int64 f6g0    = f6   * (crypto_int64) g0;
  crypto_int64 f6g1    = f6   * (crypto_int64) g1;
  crypto_int64 f6g2    = f6   * (crypto_int64) g2;
  crypto_int64 f6g3    = f6   * (crypto_int64) g3;
  crypto_int64 f6g4_19 = f6   * (crypto_int64) g4_19;
  crypto_int64 f6g5_19 = f6   * (crypto_int64) g5_19;
  crypto_int64 f6g6_19 = f6   * (crypto_int64) g6_19;
  crypto_int64 f6g7_19 = f6   * (crypto_int64) g7_19;
  crypto_int64 f6g8_19 = f6   * (crypto_int64) g8_19;
  crypto_int64 f6g9_19 = f6   * (crypto_int64) g9_19;
  crypto_int64 f7g0    = f7   * (crypto_int64) g0;
  crypto_int64 f7g1_2  = f7_2 * (crypto_int64) g1;
  crypto_int64 f7g2    = f7   * (crypto_int64) g2;
  crypto_int64 f7g3_38 = f7_2 * (crypto_int64) g3_19;
  crypto_int64 f7g4_19 = f7   * (crypto_int64) g4_19;
  crypto_int64 f7g5_38 = f7_2 * (crypto_int64) g5_19;
  crypto_int64 f7g6_19 = f7   * (crypto_int64) g6_19;
  crypto_int64 f7g7_38 = f7_2 * (crypto_int64) g7_19;
  crypto_int64 f7g8_19 = f7   * (crypto_int64) g8_19;
  crypto_int64 f7g9_38 = f7_2 * (crypto_int64) g9_19;
  crypto_int64 f8g0    = f8   * (crypto_int64) g0;
  crypto_int64 f8g1    = f8   * (crypto_int64) g1;
  crypto_int64 f8g2_19 = f8   * (crypto_int64) g2_19;
  crypto_int64 f8g3_19 = f8   * (crypto_int64) g3_19;
  crypto_int64 f8g4_19 = f8   * (crypto_int64) g4_19;
  crypto_int64 f8g5_19 = f8   * (crypto_int64) g5_19;
  crypto_int64 f8g6_19 = f8   * (crypto_int64) g6_19;
  crypto_int64 f8g7_19 = f8   * (crypto_int64) g7_19;
  crypto_int64 f8g8_19 = f8   * (crypto_int64) g8_19;
  crypto_int64 f8g9_19 = f8   * (crypto_int64) g9_19;
  crypto_int64 f9g0    = f9   * (crypto_int64) g0;
  crypto_int64 f9g1_38 = f9_2 * (crypto_int64) g1_19;
  crypto_int64 f9g2_19 = f9   * (crypto_int64) g2_19;
  crypto_int64 f9g3_38 = f9_2 * (crypto_int64) g3_19;
  crypto_int64 f9g4_19 = f9   * (crypto_int64) g4_19;
  crypto_int64 f9g5_38 = f9_2 * (crypto_int64) g5_19;
  crypto_int64 f9g6_19 = f9   * (crypto_int64) g6_19;
  crypto_int64 f9g7_38 = f9_2 * (crypto_int64) g7_19;
  crypto_int64 f9g8_19 = f9   * (crypto_int64) g8_19;
  crypto_int64 f9g9_38 = f9_2 * (crypto_int64) g9_19;
  crypto_int64 h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
  crypto_int64 h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
  crypto_int64 h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
  crypto_int64 h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
  crypto_int64 h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
  crypto_int64 h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
  crypto_int64 h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
  crypto_int64 h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
  crypto_int64 h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
  crypto_int64 h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  /*
  |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
  |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
  */

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
h = f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

void fe_sq(fe h,const fe f)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 f0_2 = 2 * f0;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f2_2 = 2 * f2;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f4_2 = 2 * f4;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f6_2 = 2 * f6;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
  crypto_int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
  crypto_int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
  crypto_int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
  crypto_int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
  crypto_int64 f0f0    = f0   * (crypto_int64) f0;
  crypto_int64 f0f1_2  = f0_2 * (crypto_int64) f1;
  crypto_int64 f0f2_2  = f0_2 * (crypto_int64) f2;
  crypto_int64 f0f3_2  = f0_2 * (crypto_int64) f3;
  crypto_int64 f0f4_2  = f0_2 * (crypto_int64) f4;
  crypto_int64 f0f5_2  = f0_2 * (crypto_int64) f5;
  crypto_int64 f0f6_2  = f0_2 * (crypto_int64) f6;
  crypto_int64 f0f7_2  = f0_2 * (crypto_int64) f7;
  crypto_int64 f0f8_2  = f0_2 * (crypto_int64) f8;
  crypto_int64 f0f9_2  = f0_2 * (crypto_int64) f9;
  crypto_int64 f1f1_2  = f1_2 * (crypto_int64) f1;
  crypto_int64 f1f2_2  = f1_2 * (crypto_int64) f2;
  crypto_int64 f1f3_4  = f1_2 * (crypto_int64) f3_2;
  crypto_int64 f1f4_2  = f1_2 * (crypto_int64) f4;
  crypto_int64 f1f5_4  = f1_2 * (crypto_int64) f5_2;
  crypto_int64 f1f6_2  = f1_2 * (crypto_int64) f6;
  crypto_int64 f1f7_4  = f1_2 * (crypto_int64) f7_2;
  crypto_int64 f1f8_2  = f1_2 * (crypto_int64) f8;
  crypto_int64 f1f9_76 = f1_2 * (crypto_int64) f9_38;
  crypto_int64 f2f2    = f2   * (crypto_int64) f2;
  crypto_int64 f2f3_2  = f2_2 * (crypto_int64) f3;
  crypto_int64 f2f4_2  = f2_2 * (crypto_int64) f4;
  crypto_int64 f2f5_2  = f2_2 * (crypto_int64) f5;
  crypto_int64 f2f6_2  = f2_2 * (crypto_int64) f6;
  crypto_int64 f2f7_2  = f2_2 * (crypto_int64) f7;
  crypto_int64 f2f8_38 = f2_2 * (crypto_int64) f8_19;
  crypto_int64 f2f9_38 = f2   * (crypto_int64) f9_38;
  crypto_int64 f3f3_2  = f3_2 * (crypto_int64) f3;
  crypto_int64 f3f4_2  = f3_2 * (crypto_int64) f4;
  crypto_int64 f3f5_4  = f3_2 * (crypto_int64) f5_2;
  crypto_int64 f3f6_2  = f3_2 * (crypto_int64) f6;
  crypto_int64 f3f7_76 = f3_2 * (crypto_int64) f7_38;
  crypto_int64 f3f8_38 = f3_2 * (crypto_int64) f8_19;
  crypto_int64 f3f9_76 = f3_2 * (crypto_int64) f9_38;
  crypto_int64 f4f4    = f4   * (crypto_int64) f4;
  crypto_int64 f4f5_2  = f4_2 * (crypto_int64) f5;
  crypto_int64 f4f6_38 = f4_2 * (crypto_int64) f6_19;
  crypto_int64 f4f7_38 = f4   * (crypto_int64) f7_38;
  crypto_int64 f4f8_38 = f4_2 * (crypto_int64) f8_19;
  crypto_int64 f4f9_38 = f4   * (crypto_int64) f9_38;
  crypto_int64 f5f5_38 = f5   * (crypto_int64) f5_38;
  crypto_int64 f5f6_38 = f5_2 * (crypto_int64) f6_19;
  crypto_int64 f5f7_76 = f5_2 * (crypto_int64) f7_38;
  crypto_int64 f5f8_38 = f5_2 * (crypto_int64) f8_19;
  crypto_int64 f5f9_76 = f5_2 * (crypto_int64) f9_38;
  crypto_int64 f6f6_19 = f6   * (crypto_int64) f6_19;
  crypto_int64 f6f7_38 = f6   * (crypto_int64) f7_38;
  crypto_int64 f6f8_38 = f6_2 * (crypto_int64) f8_19;
  crypto_int64 f6f9_38 = f6   * (crypto_int64) f9_38;
  crypto_int64 f7f7_38 = f7   * (crypto_int64) f7_38;
  crypto_int64 f7f8_38 = f7_2 * (crypto_int64) f8_19;
  crypto_int64 f7f9_76 = f7_2 * (crypto_int64) f9_38;
  crypto_int64 f8f8_19 = f8   * (crypto_int64) f8_19;
  crypto_int64 f8f9_38 = f8   * (crypto_int64) f9_38;
  crypto_int64 f9f9_38 = f9   * (crypto_int64) f9_38;
  crypto_int64 h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  crypto_int64 h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  crypto_int64 h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  crypto_int64 h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  crypto_int64 h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  crypto_int64 h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  crypto_int64 h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  crypto_int64 h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  crypto_int64 h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  crypto_int64 h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
h = 2 * f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
See fe_mul.c for discussion of implementation strategy.
*/

void fe_sq2(fe h,const fe f)
{
  crypto_int32 f0 = f[0];
  crypto_int32 f1 = f[1];
  crypto_int32 f2 = f[2];
  crypto_int32 f3 = f[3];
  crypto_int32 f4 = f[4];
  crypto_int32 f5 = f[5];
  crypto_int32 f6 = f[6];
  crypto_int32 f7 = f[7];
  crypto_int32 f8 = f[8];
  crypto_int32 f9 = f[9];
  crypto_int32 f0_2 = 2 * f0;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f2_2 = 2 * f2;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f4_2 = 2 * f4;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f6_2 = 2 * f6;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
  crypto_int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
  crypto_int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
  crypto_int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
  crypto_int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
  crypto_int64 f0f0    = f0   * (crypto_int64) f0;
  crypto_int64 f0f1_2  = f0_2 * (crypto_int64) f1;
  crypto_int64 f0f2_2  = f0_2 * (crypto_int64) f2;
  crypto_int64 f0f3_2  = f0_2 * (crypto_int64) f3;
  crypto_int64 f0f4_2  = f0_2 * (crypto_int64) f4;
  crypto_int64 f0f5_2  = f0_2 * (crypto_int64) f5;
  crypto_int64 f0f6_2  = f0_2 * (crypto_int64) f6;
  crypto_int64 f0f7_2  = f0_2 * (crypto_int64) f7;
  crypto_int64 f0f8_2  = f0_2 * (crypto_int64) f8;
  crypto_int64 f0f9_2  = f0_2 * (crypto_int64) f9;
  crypto_int64 f1f1_2  = f1_2 * (crypto_int64) f1;
  crypto_int64 f1f2_2  = f1_2 * (crypto_int64) f2;
  crypto_int64 f1f3_4  = f1_2 * (crypto_int64) f3_2;
  crypto_int64 f1f4_2  = f1_2 * (crypto_int64) f4;
  crypto_int64 f1f5_4  = f1_2 * (crypto_int64) f5_2;
  crypto_int64 f1f6_2  = f1_2 * (crypto_int64) f6;
  crypto_int64 f1f7_4  = f1_2 * (crypto_int64) f7_2;
  crypto_int64 f1f8_2  = f1_2 * (crypto_int64) f8;
  crypto_int64 f1f9_76 = f1_2 * (crypto_int64) f9_38;
  crypto_int64 f2f2    = f2   * (crypto_int64) f2;
  crypto_int64 f2f3_2  = f2_2 * (crypto_int64) f3;
  crypto_int64 f2f4_2  = f2_2 * (crypto_int64) f4;
  crypto_int64 f2f5_2  = f2_2 * (crypto_int64) f5;
  crypto_int64 f2f6_2  = f2_2 * (crypto_int64) f6;
  crypto_int64 f2f7_2  = f2_2 * (crypto_int64) f7;
  crypto_int64 f2f8_38 = f2_2 * (crypto_int64) f8_19;
  crypto_int64 f2f9_38 = f2   * (crypto_int64) f9_38;
  crypto_int64 f3f3_2  = f3_2 * (crypto_int64) f3;
  crypto_int64 f3f4_2  = f3_2 * (crypto_int64) f4;
  crypto_int64 f3f5_4  = f3_2 * (crypto_int64) f5_2;
  crypto_int64 f3f6_2  = f3_2 * (crypto_int64) f6;
  crypto_int64 f3f7_76 = f3_2 * (crypto_int64) f7_38;
  crypto_int64 f3f8_38 = f3_2 * (crypto_int64) f8_19;
  crypto_int64 f3f9_76 = f3_2 * (crypto_int64) f9_38;
  crypto_int64 f4f4    = f4   * (crypto_int64) f4;
  crypto_int64 f4f5_2  = f4_2 * (crypto_int64) f5;
  crypto_int64 f4f6_38 = f4_2 * (crypto_int64) f6_19;
  crypto_int64 f4f7_38 = f4   * (crypto_int64) f7_38;
  crypto_int64 f4f8_38 = f4_2 * (crypto_int64) f8_19;
  crypto_int64 f4f9_38 = f4   * (crypto_int64) f9_38;
  crypto_int64 f5f5_38 = f5   * (crypto_int64) f5_38;
  crypto_int64 f5f6_38 = f5_2 * (crypto_int64) f6_19;
  crypto_int64 f5f7_76 = f5_2 * (crypto_int64) f7_38;
  crypto_int64 f5f8_38 = f5_2 * (crypto_int64) f8_19;
  crypto_int64 f5f9_76 = f5_2 * (crypto_int64) f9_38;
  crypto_int64 f6f6_19 = f6   * (crypto_int64) f6_19;
  crypto_int64 f6f7_38 = f6   * (crypto_int64) f7_38;
  crypto_int64 f6f8_38 = f6_2 * (crypto_int64) f8_19;
  crypto_int64 f6f9_38 = f6   * (crypto_int64) f9_38;
  crypto_int64 f7f7_38 = f7   * (crypto_int64) f7_38;
  crypto_int64 f7f8_38 = f7_2 * (crypto_int64) f8_19;
  crypto_int64 f7f9_76 = f7_2 * (crypto_int64) f9_38;
  crypto_int64 f8f8_19 = f8   * (crypto_int64) f8_19;
  crypto_int64 f8f9_38 = f8   * (crypto_int64) f9_38;
  crypto_int64 f9f9_38 = f9   * (crypto_int64) f9_38;
  crypto_int64 h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  crypto_int64 h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  crypto_int64 h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  crypto_int64 h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  crypto_int64 h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  crypto_int64 h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  crypto_int64 h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  crypto_int64 h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  crypto_int64 h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  crypto_int64 h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  h0 += h0;
  h1 += h1;
  h2 += h2;
  h3 += h3;
  h4 += h4;
  h5 += h5;
  h6 += h6;
  h7 += h7;
  h8 += h8;
  h9 += h9;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
Ignores top bit of h.
*/

void fe_frombytes(fe h,const unsigned char *s)
{
  crypto_int64 h0 = load_4(s);
  crypto_int64 h1 = load_3(s + 4) << 6;
  crypto_int64 h2 = load_3(s + 7) << 5;
  crypto_int64 h3 = load_3(s + 10) << 3;
  crypto_int64 h4 = load_3(s + 13) << 2;
  crypto_int64 h5 = load_4(s + 16);
  crypto_int64 h6 = load_3(s + 20) << 7;
  crypto_int64 h7 = load_3(s + 23) << 5;
  crypto_int64 h8 = load_3(s + 26) << 4;
  crypto_int64 h9 = (load_3(s + 29) & 8388607) << 2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

/*
Preconditions:
  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

Write p=2^255-19; q=floor(h/p).
Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

Proof:
  Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
  Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

  Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
  Then 0<y<1.

  Write r=h-pq.
  Have 0<=r<=p-1=2^255-20.
  Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

  Write x=r+19(2^-255)r+y.
  Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

  Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
  so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
*/

void fe_tobytes(unsigned char *s,const fe h)
{
  crypto_int32 h0 = h[0];
  crypto_int32 h1 = h[1];
  crypto_int32 h2 = h[2];
  crypto_int32 h3 = h[3];
  crypto_int32 h4 = h[4];
  crypto_int32 h5 = h[5];
  crypto_int32 h6 = h[6];
  crypto_int32 h7 = h[7];
  crypto_int32 h8 = h[8];
  crypto_int32 h9 = h[9];
  crypto_int32 q;
  crypto_int32 carry0;
  crypto_int32 carry1;
  crypto_int32 carry2;
  crypto_int32 carry3;
  crypto_int32 carry4;
  crypto_int32 carry5;
  crypto_int32 carry6;
  crypto_int32 carry7;
  crypto_int32 carry8;
  crypto_int32 carry9;

  q = (19 * h9 + (((crypto_int32) 1) << 24)) >> 25;
  q = (h0 + q) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;

  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
  h0 += 19 * q;
  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

  carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
  carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
  carry9 = h9 >> 25;               h9 -= carry9 << 25;
                  /* h10 = carry9 */

  /*
  Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
  Have h0+...+2^230 h9 between 0 and 2^255-1;
  evidently 2^255 h10-2^255 q = 0.
  Goal: Output h0+...+2^230 h9.
  */

  s[0] = h0 >> 0;
  s[1] = h0 >> 8;
  s[2] = h0 >> 16;
  s[3] = (h0 >> 24) | (h1 << 2);
  s[4] = h1 >> 6;
  s[5] = h1 >> 14;
  s[6] = (h1 >> 22) | (h2 << 3);
  s[7] = h2 >> 5;
  s[8] = h2 >> 13;
  s[9] = (h2 >> 21) | (h3 << 5);
  s[10] = h3 >> 3;
  s[11] = h3 >> 11;
  s[12] = (h3 >> 19) | (h4 << 6);
  s[13] = h4 >> 2;
  s[14] = h4 >> 10;
  s[15] = h4 >> 18;
  s[16] = h5 >> 0;
  s[17] = h5 >> 8;
  s[18] = h5 >> 16;
  s[19] = (h5 >> 24) | (h6 << 1);
  s[20] = h6 >> 7;
  s[21] = h6 >> 15;
  s[22] = (h6 >> 23) | (h7 << 3);
  s[23] = h7 >> 5;
  s[24] = h7 >> 13;
  s[25] = (h7 >> 21) | (h8 << 4);
  s[26] = h8 >> 4;
  s[27] = h8 >> 12;
  s[28] = (h8 >> 20) | (h9 << 6);
  s[29] = h9 >> 2;
  s[30] = h9 >> 10;
  s[31] = h9 >> 18;
}

static int fe_isnegative(const fe f)
{
	unsigned char s[32];
	fe_tobytes(s, f);
	return s[0] & 1;
}

/* Returns 0 if f==0, non-zero if f!=0 */
static int fe_isnonzero(const fe f)
{
	unsigned char s[32];
	unsigned char d = 0;
	int i;
	fe_tobytes(s, f);
	for (i = 0; i < 32; i++) d |= s[i];
	return (int)d;
}

/* Compute z^((q-5)/8) — used in square root computation */
static void fe_pow22523(fe out, const fe z)
{
	fe t0, t1, t2;
	int i;
	fe_sq(t0,z); for (i=1;i<1;++i) fe_sq(t0,t0);
	fe_sq(t1,t0); for (i=1;i<2;++i) fe_sq(t1,t1);
	fe_mul(t1,z,t1);
	fe_mul(t0,t0,t1);
	fe_sq(t0,t0); for (i=1;i<1;++i) fe_sq(t0,t0);
	fe_mul(t0,t1,t0);
	fe_sq(t1,t0); for (i=1;i<5;++i) fe_sq(t1,t1);
	fe_mul(t0,t1,t0);
	fe_sq(t1,t0); for (i=1;i<10;++i) fe_sq(t1,t1);
	fe_mul(t1,t1,t0);
	fe_sq(t2,t1); for (i=1;i<20;++i) fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t1,t1); for (i=1;i<10;++i) fe_sq(t1,t1);
	fe_mul(t0,t1,t0);
	fe_sq(t1,t0); for (i=1;i<50;++i) fe_sq(t1,t1);
	fe_mul(t1,t1,t0);
	fe_sq(t2,t1); for (i=1;i<100;++i) fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t1,t1); for (i=1;i<50;++i) fe_sq(t1,t1);
	fe_mul(t0,t1,t0);
	fe_sq(t0,t0); for (i=1;i<2;++i) fe_sq(t0,t0);
	fe_mul(out,t0,z);
}

/* Compute z^(2^255 - 21) — field inversion */
static void fe_invert(fe out, const fe z)
{
	fe t0, t1, t2, t3;
	int i;
	fe_sq(t0,z); for (i=1;i<1;++i) fe_sq(t0,t0);
	fe_sq(t1,t0); for (i=1;i<2;++i) fe_sq(t1,t1);
	fe_mul(t1,z,t1);
	fe_mul(t0,t0,t1);
	fe_sq(t2,t0); for (i=1;i<1;++i) fe_sq(t2,t2);
	fe_mul(t1,t1,t2);
	fe_sq(t2,t1); for (i=1;i<5;++i) fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t2,t1); for (i=1;i<10;++i) fe_sq(t2,t2);
	fe_mul(t2,t2,t1);
	fe_sq(t3,t2); for (i=1;i<20;++i) fe_sq(t3,t3);
	fe_mul(t2,t3,t2);
	fe_sq(t2,t2); for (i=1;i<10;++i) fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t2,t1); for (i=1;i<50;++i) fe_sq(t2,t2);
	fe_mul(t2,t2,t1);
	fe_sq(t3,t2); for (i=1;i<100;++i) fe_sq(t3,t3);
	fe_mul(t2,t3,t2);
	fe_sq(t2,t2); for (i=1;i<50;++i) fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t1,t1); for (i=1;i<5;++i) fe_sq(t1,t1);
	fe_mul(out,t1,t0);
}

/*************************************\
*  Twisted Edwards group arithmetic   *
\*************************************/

typedef struct { fe X; fe Y; fe Z; }         ge_p2;
typedef struct { fe X; fe Y; fe Z; fe T; }   ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; }   ge_p1p1;
typedef struct { fe yplusx; fe yminusx; fe xy2d; }             ge_precomp;
typedef struct { fe YplusX; fe YminusX; fe Z; fe T2d; }        ge_cached;

void ge_p2_0(ge_p2 *h)
{
  fe_0(h->X);
  fe_1(h->Y);
  fe_1(h->Z);
}

extern void ge_p3_to_p2(ge_p2 *r,const ge_p3 *p)
{
  fe_copy(r->X,p->X);
  fe_copy(r->Y,p->Y);
  fe_copy(r->Z,p->Z);
}

static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p)
{
	fe_add(r->YplusX, p->Y, p->X);
	fe_sub(r->YminusX, p->Y, p->X);
	fe_copy(r->Z, p->Z);
	fe_mul(r->T2d, p->T, d2);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p)
{
	fe_mul(r->X, p->X, p->T);
	fe_mul(r->Y, p->Y, p->Z);
	fe_mul(r->Z, p->Z, p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p)
{
	fe_mul(r->X, p->X, p->T);
	fe_mul(r->Y, p->Y, p->Z);
	fe_mul(r->Z, p->Z, p->T);
	fe_mul(r->T, p->X, p->Y);
}

static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
	fe t0;
	fe_sq(r->X, p->X);
	fe_sq(r->Z, p->Y);
	fe_sq2(r->T, p->Z);
	fe_add(r->Y, p->X, p->Y);
	fe_sq(t0, r->Y);
	fe_add(r->Y, r->Z, r->X);
	fe_sub(r->Z, r->Z, r->X);
	fe_sub(r->X, t0, r->Y);
	fe_sub(r->T, r->T, r->Z);
}

static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p)
{
	ge_p2 q;
	ge_p3_to_p2(&q, p);
	ge_p2_dbl(r, &q);
}

static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
	fe t0;
	fe_add(r->X, p->Y, p->X);
	fe_sub(r->Y, p->Y, p->X);
	fe_mul(r->Z, r->X, q->YplusX);
	fe_mul(r->Y, r->Y, q->YminusX);
	fe_mul(r->T, q->T2d, p->T);
	fe_mul(r->X, p->Z, q->Z);
	fe_add(t0, r->X, r->X);
	fe_sub(r->X, r->Z, r->Y);
	fe_add(r->Y, r->Z, r->Y);
	fe_add(r->Z, t0, r->T);
	fe_sub(r->T, t0, r->T);
}

static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
	fe t0;
	fe_add(r->X, p->Y, p->X);
	fe_sub(r->Y, p->Y, p->X);
	fe_mul(r->Z, r->X, q->YminusX);
	fe_mul(r->Y, r->Y, q->YplusX);
	fe_mul(r->T, q->T2d, p->T);
	fe_mul(r->X, p->Z, q->Z);
	fe_add(t0, r->X, r->X);
	fe_sub(r->X, r->Z, r->Y);
	fe_add(r->Y, r->Z, r->Y);
	fe_sub(r->Z, t0, r->T);
	fe_add(r->T, t0, r->T);
}

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
	fe t0;
	fe_add(r->X, p->Y, p->X);
	fe_sub(r->Y, p->Y, p->X);
	fe_mul(r->Z, r->X, q->yplusx);
	fe_mul(r->Y, r->Y, q->yminusx);
	fe_mul(r->T, q->xy2d, p->T);
	fe_add(t0, p->Z, p->Z);
	fe_sub(r->X, r->Z, r->Y);
	fe_add(r->Y, r->Z, r->Y);
	fe_add(r->Z, t0, r->T);
	fe_sub(r->T, t0, r->T);
}

static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
	fe t0;
	fe_add(r->X, p->Y, p->X);
	fe_sub(r->Y, p->Y, p->X);
	fe_mul(r->Z, r->X, q->yminusx);
	fe_mul(r->Y, r->Y, q->yplusx);
	fe_mul(r->T, q->xy2d, p->T);
	fe_add(t0, p->Z, p->Z);
	fe_sub(r->X, r->Z, r->Y);
	fe_add(r->Y, r->Z, r->Y);
	fe_sub(r->Z, t0, r->T);
	fe_add(r->T, t0, r->T);
}

/* Decode compressed point, storing -A (negate X) for verification */
static int ge_frombytes_negate_vartime(ge_p3 *h, const unsigned char *s)
{
	fe u, v, v3, vxx, check;
	fe_frombytes(h->Y, s);
	fe_1(h->Z);
	fe_sq(u, h->Y);
	fe_mul(v, u, d);
	fe_sub(u, u, h->Z);
	fe_add(v, v, h->Z);
	fe_sq(v3, v);
	fe_mul(v3, v3, v);
	fe_sq(h->X, v3);
	fe_mul(h->X, h->X, v);
	fe_mul(h->X, h->X, u);
	fe_pow22523(h->X, h->X);
	fe_mul(h->X, h->X, v3);
	fe_mul(h->X, h->X, u);
	fe_sq(vxx, h->X);
	fe_mul(vxx, vxx, v);
	fe_sub(check, vxx, u);
	if (fe_isnonzero(check)) {
		fe_add(check, vxx, u);
		if (fe_isnonzero(check)) return -1;
		fe_mul(h->X, h->X, sqrtm1);
	}
	if (fe_isnegative(h->X) == (s[31] >> 7))
		fe_neg(h->X, h->X);
	fe_mul(h->T, h->X, h->Y);
	return 0;
}

static void ge_tobytes(unsigned char *s, const ge_p2 *h)
{
	fe recip, x, y;
	fe_invert(recip, h->Z);
	fe_mul(x, h->X, recip);
	fe_mul(y, h->Y, recip);
	fe_tobytes(s, y);
	s[31] ^= fe_isnegative(x) << 7;
}

/***************************\
*  Scalar reduction mod L   *
\***************************/

/*
Input:
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/

void sc_reduce(unsigned char *s)
{
  crypto_int64 s0 = 2097151 & load_3(s);
  crypto_int64 s1 = 2097151 & (load_4(s + 2) >> 5);
  crypto_int64 s2 = 2097151 & (load_3(s + 5) >> 2);
  crypto_int64 s3 = 2097151 & (load_4(s + 7) >> 7);
  crypto_int64 s4 = 2097151 & (load_4(s + 10) >> 4);
  crypto_int64 s5 = 2097151 & (load_3(s + 13) >> 1);
  crypto_int64 s6 = 2097151 & (load_4(s + 15) >> 6);
  crypto_int64 s7 = 2097151 & (load_3(s + 18) >> 3);
  crypto_int64 s8 = 2097151 & load_3(s + 21);
  crypto_int64 s9 = 2097151 & (load_4(s + 23) >> 5);
  crypto_int64 s10 = 2097151 & (load_3(s + 26) >> 2);
  crypto_int64 s11 = 2097151 & (load_4(s + 28) >> 7);
  crypto_int64 s12 = 2097151 & (load_4(s + 31) >> 4);
  crypto_int64 s13 = 2097151 & (load_3(s + 34) >> 1);
  crypto_int64 s14 = 2097151 & (load_4(s + 36) >> 6);
  crypto_int64 s15 = 2097151 & (load_3(s + 39) >> 3);
  crypto_int64 s16 = 2097151 & load_3(s + 42);
  crypto_int64 s17 = 2097151 & (load_4(s + 44) >> 5);
  crypto_int64 s18 = 2097151 & (load_3(s + 47) >> 2);
  crypto_int64 s19 = 2097151 & (load_4(s + 49) >> 7);
  crypto_int64 s20 = 2097151 & (load_4(s + 52) >> 4);
  crypto_int64 s21 = 2097151 & (load_3(s + 55) >> 1);
  crypto_int64 s22 = 2097151 & (load_4(s + 57) >> 6);
  crypto_int64 s23 = (load_4(s + 60) >> 3);
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;
  crypto_int64 carry10;
  crypto_int64 carry11;
  crypto_int64 carry12;
  crypto_int64 carry13;
  crypto_int64 carry14;
  crypto_int64 carry15;
  crypto_int64 carry16;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  s23 = 0;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  s22 = 0;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  s21 = 0;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  s20 = 0;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  s19 = 0;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  s18 = 0;

  carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
  carry12 = (s12 + (1<<20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
  carry14 = (s14 + (1<<20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
  carry16 = (s16 + (1<<20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

  carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
  carry13 = (s13 + (1<<20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
  carry15 = (s15 + (1<<20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  s17 = 0;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  s16 = 0;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  s15 = 0;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  s14 = 0;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  s13 = 0;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

  carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
  carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

  s[0] = s0 >> 0;
  s[1] = s0 >> 8;
  s[2] = (s0 >> 16) | (s1 << 5);
  s[3] = s1 >> 3;
  s[4] = s1 >> 11;
  s[5] = (s1 >> 19) | (s2 << 2);
  s[6] = s2 >> 6;
  s[7] = (s2 >> 14) | (s3 << 7);
  s[8] = s3 >> 1;
  s[9] = s3 >> 9;
  s[10] = (s3 >> 17) | (s4 << 4);
  s[11] = s4 >> 4;
  s[12] = s4 >> 12;
  s[13] = (s4 >> 20) | (s5 << 1);
  s[14] = s5 >> 7;
  s[15] = (s5 >> 15) | (s6 << 6);
  s[16] = s6 >> 2;
  s[17] = s6 >> 10;
  s[18] = (s6 >> 18) | (s7 << 3);
  s[19] = s7 >> 5;
  s[20] = s7 >> 13;
  s[21] = s8 >> 0;
  s[22] = s8 >> 8;
  s[23] = (s8 >> 16) | (s9 << 5);
  s[24] = s9 >> 3;
  s[25] = s9 >> 11;
  s[26] = (s9 >> 19) | (s10 << 2);
  s[27] = s10 >> 6;
  s[28] = (s10 >> 14) | (s11 << 7);
  s[29] = s11 >> 1;
  s[30] = s11 >> 9;
  s[31] = s11 >> 17;
}

/***********************************\
*  Double-scalar multiplication     *
*  r = a*A + b*B                    *
\***********************************/

/* Precomputed odd multiples of the base point B (8 entries) */
static const ge_precomp Bi[8] = {
#define ENTRY(a,b,c,d,e,f,g,h,i,j, \
              k,l,m,n,o,p,q,r,s,t, \
              u,v,w,x,y,z,A,B,C,D) \
 { {a,b,c,d,e,f,g,h,i,j}, {k,l,m,n,o,p,q,r,s,t}, {u,v,w,x,y,z,A,B,C,D} }
ENTRY( 25967493,-14356035, 29566456,  3660896,-12694345,  4014787, 27544626,-11754271, -6079156,  2047605,
      -12545711,   934262, -2722910,  3049990,  -727428,  9406986, 12720692,  5043384, 19500929,-15469378,
       -8738181,  4489570,  9688441,-14785194, 10184609,-12363380, 29287919, 11864899,-24514362, -4438546),
ENTRY( 15636291, -9688557, 24204773, -7912398,   616977,-16685262, 27787600,-14772189, 28944400, -1550024,
       16568933,  4717097,-11556148, -1102322, 15682896,-11807043, 16354577,-11775962,  7689662, 11199574,
       30464156, -5976125,-11779434,-15670865, 23220365, 15915852,  7512774, 10017326,-17749093, -9920357),
ENTRY( 10861363, 11473154, 27284546,  1981175,-30064349, 12577861, 32867885, 14515107,-15438304, 10819380,
        4708026,  6336745, 20377586,  9066809,-11272109,  6594696,-25653668, 12483688,-12668491,  5581306,
       19563160, 16186464,-29386857,  4097519, 10237984, -4348115, 28542350, 13850243,-23678021,-15815942),
ENTRY(  5153746,  9909285,  1723747, -2777874, 30523605,  5516873, 19480852,  5230134,-23952439,-15175766,
      -30269007, -3463509,  7665486, 10083793, 28475525,  1649722, 20654025, 16520125, 30598449,  7715701,
       28881845, 14381568,  9657904,  3680757,-20181635,  7843316,-31400660,  1370708, 29794553, -1409300),
ENTRY(-22518993, -6692182, 14201702, -8745502,-23510406,  8844726, 18474211, -1361450,-13062696, 13821877,
       -6455177, -7839871,  3374702, -4740862,-27098617,-10571707, 31655028, -7212327, 18853322,-14220951,
        4566830,-12963868,-28974889,-12240689, -7602672, -2830569, -8514358,-10431137,  2207753, -3209784),
ENTRY(-25154831, -4185821, 29681144,  7868801, -6854661, -9423865,-12437364,  -663000,-31111463,-16132436,
       25576264, -2703214,  7349804,-11814844, 16472782,  9300885,  3844789, 15725684,   171356,  6466918,
       23103977, 13316479,  9739013,-16149481,   817875,-15038942,  8965339,-14088058,-30714912, 16193877),
ENTRY(-33521811,  3180713, -2394130, 14003687,-16903474,-16270840, 17238398,  4729455,-18074513,  9256800,
      -25182317, -4174131, 32336398,  5036987,-21236817, 11360617, 22616405,  9761698,-19827198,   630305,
      -13720693,  2639453,-24237460, -7406481,  9494427, -5774029, -6554551,-15960994, -2449256,-14291300),
ENTRY( -3151181, -5046075,  9282714,  6866145,-31907062,  -863023,-18940575, 15033784, 25105118, -7894876,
      -24326370, 15950226,-31801215,-14592823,-11662737, -5090925,  1573892, -2625887,  2198790,-15804619,
       -3099351, 10324967, -2241613,  7453183, -5446979, -2735503,-13812022,-16236442,-32461234,-12290683),
#undef ENTRY
};

static void slide(signed char *r,const unsigned char *a)
{
  int i;
  int b;
  int k;

  for (i = 0;i < 256;++i)
    r[i] = crypto_int8_bitmod_01(a[i >> 3],i);

  for (i = 0;i < 256;++i)
    if (r[i]) {
      for (b = 1;b <= 6 && i + b < 256;++b) {
        if (r[i + b]) {
          if (r[i] + (r[i + b] << b) <= 15) {
            r[i] += r[i + b] << b; r[i + b] = 0;
          } else if (r[i] - (r[i + b] << b) >= -15) {
            r[i] -= r[i + b] << b;
            for (k = i + b;k < 256;++k) {
              if (!r[k]) {
                r[k] = 1;
                break;
              }
              r[k] = 0;
            }
          } else
            break;
        }
      }
    }

}

/* Compute r = a*A + b*B (A is already negated by ge_frombytes_negate_vartime) */
/*
r = a * A + b * B
where a = a[0]+256*a[1]+...+256^31 a[31].
and b = b[0]+256*b[1]+...+256^31 b[31].
B is the Ed25519 base point (x,4/5) with x positive.
*/

void ge_double_scalarmult_vartime(ge_p2 *r,const unsigned char *a,const ge_p3 *A,const unsigned char *b)
{
  signed char aslide[256];
  signed char bslide[256];
  ge_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
  ge_p1p1 t;
  ge_p3 u;
  ge_p3 A2;
  int i;

  slide(aslide,a);
  slide(bslide,b);

  ge_p3_to_cached(&Ai[0],A);
  ge_p3_dbl(&t,A); ge_p1p1_to_p3(&A2,&t);
  ge_add(&t,&A2,&Ai[0]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[1],&u);
  ge_add(&t,&A2,&Ai[1]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[2],&u);
  ge_add(&t,&A2,&Ai[2]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[3],&u);
  ge_add(&t,&A2,&Ai[3]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[4],&u);
  ge_add(&t,&A2,&Ai[4]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[5],&u);
  ge_add(&t,&A2,&Ai[5]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[6],&u);
  ge_add(&t,&A2,&Ai[6]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[7],&u);

  ge_p2_0(r);

  for (i = 255;i >= 0;--i) {
    if (aslide[i] || bslide[i]) break;
  }

  for (;i >= 0;--i) {
    ge_p2_dbl(&t,r);

    if (aslide[i] > 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_add(&t,&u,&Ai[aslide[i]/2]);
    } else if (aslide[i] < 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_sub(&t,&u,&Ai[(-aslide[i])/2]);
    }

    if (bslide[i] > 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_madd(&t,&u,&Bi[bslide[i]/2]);
    } else if (bslide[i] < 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_msub(&t,&u,&Bi[(-bslide[i])/2]);
    }

    ge_p1p1_to_p2(r,&t);
  }
}

/***********************\
*  Ed25519 verification *
\***********************/

/* Constant-time 32-byte compare: returns 0 if equal, non-zero if different */
static int crypto_verify32(const unsigned char *x, const unsigned char *y)
{
	unsigned int d = 0;
	int i;
	for (i = 0; i < 32; i++) d |= x[i] ^ y[i];
	return (int)(((unsigned int)(d - 1) >> 31) - 1);
}

/*
 * Reduce a 64-byte SHA-512 hash to a 32-byte scalar mod L.
 * Result written to reduced[0..31]; expanded is consumed in place via a copy.
 */
static void eddsa_reduce(u8 reduced[32], const u8 expanded[64])
{
	u8 tmp[64];
	memcpy(tmp, expanded, 64);
	sc_reduce(tmp);
	memcpy(reduced, tmp, 32);
}

/*
 * Verify the EdDSA equation: s*B == R + h*A
 * Equivalently (with -A from ge_frombytes_negate_vartime):
 *   s*B + h*(-A) == R
 *
 * Returns 0 on success, non-zero on failure.
 */
static int eddsa_check_equation(const u8 signature[64],
                                const u8 public_key[32],
                                const u8 h[32])
{
	ge_p3 A;
	ge_p2 R;
	unsigned char Rbytes[32];

	/* Top 3 bits of s must be zero (s < 2^253) */
	if (signature[63] & 224)
		return -1;

	/* Decode public key as -A */
	if (ge_frombytes_negate_vartime(&A, public_key) != 0)
		return -1;

	/* Compute s*B + h*(-A) = s*B - h*A */
	ge_double_scalarmult_vartime(&R, h, &A, signature + 32);

	/* Encode and compare with R from the signature */
	ge_tobytes(Rbytes, &R);
	return crypto_verify32(Rbytes, signature);
}

/*
 * Compute SHA-512(R || A || hdr_bytes || body) and reduce mod L.
 * hdr is fed as its 8-byte little-endian representation.
 */
static void ed25519_hash_reduce(u8 h[32],
                                const u8 *R,    size_t R_len,
                                const u8 *A,    size_t A_len,
                                uint64_t  hdr,
                                const u8 *body, size_t body_len)
{
	u8 digest[64];
	sha512_ctx_t ctx;
	sha512_init  (&ctx);
	sha512_update(&ctx, R,    R_len);
	sha512_update(&ctx, A,    A_len);
	sha512_update(&ctx, (const u8 *)&hdr, 8);
	sha512_update(&ctx, body, body_len);
	sha512_final (&ctx, digest);
	eddsa_reduce(h, digest);
}

/*********************\
*  Crypto context     *
\*********************/

struct crypto_ctx {
	u8     pubkey[32];
	size_t pubkey_idx;
	u8     sigbuf[64];
	size_t sig_idx;
};

crypto_ctx_t *crypto_init(crypto_algo_t algo)
{
	if (algo != CRYPTO_ALGO_ED25519)
		return NULL;
	crypto_ctx_t *ctx = malloc(sizeof(struct crypto_ctx));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(struct crypto_ctx));
	return ctx;
}

void crypto_exit(crypto_ctx_t *ctx)
{
	if (!ctx)
		return;
	volatile u8 *p = (u8 *)ctx;
	for (size_t i = 0; i < sizeof(struct crypto_ctx); i++) p[i] = 0;
	free(ctx);
}

int crypto_set_pubkey(crypto_ctx_t *ctx, const uint8_t *data, size_t len)
{
	if (ctx->pubkey_idx + len > sizeof(ctx->pubkey))
		return -1;
	memcpy(ctx->pubkey + ctx->pubkey_idx, data, len);
	ctx->pubkey_idx += len;
	return 0;
}

int crypto_set_signature(crypto_ctx_t *ctx, const uint8_t *data, size_t len)
{
	if (ctx->sig_idx + len > sizeof(ctx->sigbuf))
		return -1;
	memcpy(ctx->sigbuf + ctx->sig_idx, data, len);
	ctx->sig_idx += len;
	return 0;
}

int crypto_verify_signature(crypto_ctx_t *ctx, uint64_t hdr,
                             const void *body, size_t body_len)
{
	u8 h[32];
	ed25519_hash_reduce(h,
	                    ctx->sigbuf, 32,
	                    ctx->pubkey, 32,
	                    hdr,
	                    (const u8 *)body, body_len);
	int ret = eddsa_check_equation(ctx->sigbuf, ctx->pubkey, h);
	DBG("[CRYPTO] Signature check %s\n", ret ? "FAILED" : "PASSED");
	volatile u8 *p = h;
	for (size_t i = 0; i < 32; i++) p[i] = 0;
	memset(ctx->sigbuf, 0, sizeof(ctx->sigbuf));
	ctx->sig_idx = 0;
	return ret ? -1 : 0;
}

/***********************\
*  Built-in self-tests  *
\***********************/

int crypto_selftest(void)
{
	DBG("[CRYPTO] SHA512 self-test (empty message)\n");

	/*
	 * SHA-512("") — FIPS 180-4:
	 *   cf83e135 7eefb8bd f1542850 d66d8007 d620e405 0b5715dc 83f4a921 d36ce9ce
	 *   47d0d13c 5d85f2b0 ff8318d2 877eec2f 63b931bd 47417a81 a538327a f927da3e
	 */
	static const u8 sha512_empty[64] = {
		0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,
		0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
		0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,
		0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
		0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,
		0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
		0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
		0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e,
	};
	sha512_ctx_t sctx;
	u8 hash[64];
	sha512_init(&sctx);
	sha512_final(&sctx, hash);
	if (memcmp(hash, sha512_empty, 64) != 0)
		return -1;

	DBG("[CRYPTO] ED25519 self-test (empty message)\n");

	/*
	 * Ed25519 RFC 8032 §5.1 Test Vector 1 (empty message).
	 */
	static const u8 kKatPk[32] = {
		0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
		0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
		0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
		0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a,
	};
	static const u8 kKatSig[64] = {
		0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
		0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
		0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
		0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
		0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
		0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
		0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
		0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b,
	};

	/* Compute h = SHA-512(R || A || empty_msg) mod L */
	u8 h[32];
	u8 digest[64];
	sha512_ctx_t hctx;
	sha512_init  (&hctx);
	sha512_update(&hctx, kKatSig, 32);
	sha512_update(&hctx, kKatPk,  32);
	sha512_final (&hctx, digest);
	eddsa_reduce(h, digest);

	if (eddsa_check_equation(kKatSig, kKatPk, h) != 0)
		return -2;

	/* Flipped-bit must fail */
	u8 bad_sig[64];
	memcpy(bad_sig, kKatSig, 64);
	bad_sig[0] ^= 0x01;
	if (eddsa_check_equation(bad_sig, kKatPk, h) == 0)
		return -3;

	return 0;
}
