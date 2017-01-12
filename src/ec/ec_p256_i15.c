/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
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
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

/*
 * If BR_NO_ARITH_SHIFT is undefined, or defined to 0, then we _assume_
 * that right-shifting a signed negative integer copies the sign bit
 * (arithmetic right-shift). This is "implementation-defined behaviour",
 * i.e. it is not undefined, but it may differ between compilers. Each
 * compiler is supposed to document its behaviour in that respect. GCC
 * explicitly defines that an arithmetic right shift is used. We expect
 * all other compilers to do the same, because underlying CPU offer an
 * arithmetic right shift opcode that could not be used otherwise.
 */
#if BR_NO_ARITH_SHIFT
#define ARSH(x, n)   (((uint32_t)(x) >> (n)) \
                    | ((-((uint32_t)(x) >> 31)) << (32 - (n))))
#else
#define ARSH(x, n)   ((*(int32_t *)&(x)) >> (n))
#endif

/*
 * Convert an integer from unsigned big-endian encoding to a sequence of
 * 13-bit words in little-endian order. The final "partial" word is
 * returned.
 */
static uint32_t
be8_to_le13(uint32_t *dst, const unsigned char *src, size_t len)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len -- > 0) {
		acc |= (uint32_t)src[len] << acc_len;
		acc_len += 8;
		if (acc_len >= 13) {
			*dst ++ = acc & 0x1FFF;
			acc >>= 13;
			acc_len -= 13;
		}
	}
	return acc;
}

/*
 * Convert an integer (13-bit words, little-endian) to unsigned
 * big-endian encoding. The total encoding length is provided; all
 * the destination bytes will be filled.
 */
static void
le13_to_be8(unsigned char *dst, size_t len, const uint32_t *src)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len -- > 0) {
		if (acc_len < 8) {
			acc |= (*src ++) << acc_len;
			acc_len += 13;
		}
		dst[len] = (unsigned char)acc;
		acc >>= 8;
		acc_len -= 8;
	}
}

/*
 * Normalise an array of words to a strict 13 bits per word. Returned
 * value is the resulting carry. The source (w) and destination (d)
 * arrays may be identical, but shall not overlap partially.
 */
static inline uint32_t
norm13(uint32_t *d, const uint32_t *w, size_t len)
{
	size_t u;
	uint32_t cc;

	cc = 0;
	for (u = 0; u < len; u ++) {
		int32_t z;

		z = w[u] + cc;
		d[u] = z & 0x1FFF;
		cc = ARSH(z, 13);
	}
	return cc;
}

/*
 * mul20() multiplies two 260-bit integers together. Each word must fit
 * on 13 bits; source operands use 20 words, destination operand
 * receives 40 words. All overlaps allowed.
 *
 * 
 */

#if BR_SLOW_MUL15

static void
mul20(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	/*
	 * Two-level Karatsuba: turns a 20x20 multiplication into
	 * nine 5x5 multiplications. We use 13-bit words but do not
	 * propagate carries immediately, so words may expand:
	 *
	 *  - First Karatsuba decomposition turns the 20x20 mul on
	 *    13-bit words into three 10x10 muls, two on 13-bit words
	 *    and one on 14-bit words.
	 *
	 *  - Second Karatsuba decomposition further splits these into:
	 *
	 *     * four 5x5 muls on 13-bit words
	 *     * four 5x5 muls on 14-bit words
	 *     * one 5x5 mul on 15-bit words
	 *
	 * Highest word value is 8191, 16382 or 32764, for 13-bit, 14-bit
	 * or 15-bit words, respectively.
	 */
	uint32_t u[45], v[45], w[90];
	uint32_t cc;
	int i;

#define ZADD(dw, d_off, s1w, s1_off, s2w, s2_off)   do { \
		(dw)[5 * (d_off) + 0] = (s1w)[5 * (s1_off) + 0] \
			+ (s2w)[5 * (s2_off) + 0]; \
		(dw)[5 * (d_off) + 1] = (s1w)[5 * (s1_off) + 1] \
			+ (s2w)[5 * (s2_off) + 1]; \
		(dw)[5 * (d_off) + 2] = (s1w)[5 * (s1_off) + 2] \
			+ (s2w)[5 * (s2_off) + 2]; \
		(dw)[5 * (d_off) + 3] = (s1w)[5 * (s1_off) + 3] \
			+ (s2w)[5 * (s2_off) + 3]; \
		(dw)[5 * (d_off) + 4] = (s1w)[5 * (s1_off) + 4] \
			+ (s2w)[5 * (s2_off) + 4]; \
	} while (0)

#define ZADDT(dw, d_off, sw, s_off)   do { \
		(dw)[5 * (d_off) + 0] += (sw)[5 * (s_off) + 0]; \
		(dw)[5 * (d_off) + 1] += (sw)[5 * (s_off) + 1]; \
		(dw)[5 * (d_off) + 2] += (sw)[5 * (s_off) + 2]; \
		(dw)[5 * (d_off) + 3] += (sw)[5 * (s_off) + 3]; \
		(dw)[5 * (d_off) + 4] += (sw)[5 * (s_off) + 4]; \
	} while (0)

#define ZSUB2F(dw, d_off, s1w, s1_off, s2w, s2_off)   do { \
		(dw)[5 * (d_off) + 0] -= (s1w)[5 * (s1_off) + 0] \
			+ (s2w)[5 * (s2_off) + 0]; \
		(dw)[5 * (d_off) + 1] -= (s1w)[5 * (s1_off) + 1] \
			+ (s2w)[5 * (s2_off) + 1]; \
		(dw)[5 * (d_off) + 2] -= (s1w)[5 * (s1_off) + 2] \
			+ (s2w)[5 * (s2_off) + 2]; \
		(dw)[5 * (d_off) + 3] -= (s1w)[5 * (s1_off) + 3] \
			+ (s2w)[5 * (s2_off) + 3]; \
		(dw)[5 * (d_off) + 4] -= (s1w)[5 * (s1_off) + 4] \
			+ (s2w)[5 * (s2_off) + 4]; \
	} while (0)

#define CPR1(w, cprcc)   do { \
		uint32_t cprz = (w) + cprcc; \
		(w) = cprz & 0x1FFF; \
		cprcc = cprz >> 13; \
	} while (0)

#define CPR(dw, d_off)   do { \
		uint32_t cprcc; \
		cprcc = 0; \
		CPR1((dw)[(d_off) + 0], cprcc); \
		CPR1((dw)[(d_off) + 1], cprcc); \
		CPR1((dw)[(d_off) + 2], cprcc); \
		CPR1((dw)[(d_off) + 3], cprcc); \
		CPR1((dw)[(d_off) + 4], cprcc); \
		CPR1((dw)[(d_off) + 5], cprcc); \
		CPR1((dw)[(d_off) + 6], cprcc); \
		CPR1((dw)[(d_off) + 7], cprcc); \
		CPR1((dw)[(d_off) + 8], cprcc); \
		(dw)[(d_off) + 9] = cprcc; \
	} while (0)

	memcpy(u, a, 20 * sizeof *a);
	ZADD(u, 4, a, 0, a, 1);
	ZADD(u, 5, a, 2, a, 3);
	ZADD(u, 6, a, 0, a, 2);
	ZADD(u, 7, a, 1, a, 3);
	ZADD(u, 8, u, 6, u, 7);

	memcpy(v, b, 20 * sizeof *b);
	ZADD(v, 4, b, 0, b, 1);
	ZADD(v, 5, b, 2, b, 3);
	ZADD(v, 6, b, 0, b, 2);
	ZADD(v, 7, b, 1, b, 3);
	ZADD(v, 8, v, 6, v, 7);

	/*
	 * Do the eight first 8x8 muls. Source words are at most 16382
	 * each, so we can add product results together "as is" in 32-bit
	 * words.
	 */
	for (i = 0; i < 40; i += 5) {
		w[(i << 1) + 0] = MUL15(u[i + 0], v[i + 0]);
		w[(i << 1) + 1] = MUL15(u[i + 0], v[i + 1])
			+ MUL15(u[i + 1], v[i + 0]);
		w[(i << 1) + 2] = MUL15(u[i + 0], v[i + 2])
			+ MUL15(u[i + 1], v[i + 1])
			+ MUL15(u[i + 2], v[i + 0]);
		w[(i << 1) + 3] = MUL15(u[i + 0], v[i + 3])
			+ MUL15(u[i + 1], v[i + 2])
			+ MUL15(u[i + 2], v[i + 1])
			+ MUL15(u[i + 3], v[i + 0]);
		w[(i << 1) + 4] = MUL15(u[i + 0], v[i + 4])
			+ MUL15(u[i + 1], v[i + 3])
			+ MUL15(u[i + 2], v[i + 2])
			+ MUL15(u[i + 3], v[i + 1])
			+ MUL15(u[i + 4], v[i + 0]);
		w[(i << 1) + 5] = MUL15(u[i + 1], v[i + 4])
			+ MUL15(u[i + 2], v[i + 3])
			+ MUL15(u[i + 3], v[i + 2])
			+ MUL15(u[i + 4], v[i + 1]);
		w[(i << 1) + 6] = MUL15(u[i + 2], v[i + 4])
			+ MUL15(u[i + 3], v[i + 3])
			+ MUL15(u[i + 4], v[i + 2]);
		w[(i << 1) + 7] = MUL15(u[i + 3], v[i + 4])
			+ MUL15(u[i + 4], v[i + 3]);
		w[(i << 1) + 8] = MUL15(u[i + 4], v[i + 4]);
		w[(i << 1) + 9] = 0;
	}

	/*
	 * For the 9th multiplication, source words are up to 32764,
	 * so we must do some carry propagation. If we add up to
	 * 4 products and the carry is no more than 524224, then the
	 * result fits in 32 bits, and the next carry will be no more
	 * than 524224 (because 4*(32764^2)+524224 < 8192*524225).
	 *
	 * We thus just skip one of the products in the middle word,
	 * then do a carry propagation (this reduces words to 13 bits
	 * each, except possibly the last, which may use up to 17 bits
	 * or so), then add the missing product.
	 */
	w[80 + 0] = MUL15(u[40 + 0], v[40 + 0]);
	w[80 + 1] = MUL15(u[40 + 0], v[40 + 1])
		+ MUL15(u[40 + 1], v[40 + 0]);
	w[80 + 2] = MUL15(u[40 + 0], v[40 + 2])
		+ MUL15(u[40 + 1], v[40 + 1])
		+ MUL15(u[40 + 2], v[40 + 0]);
	w[80 + 3] = MUL15(u[40 + 0], v[40 + 3])
		+ MUL15(u[40 + 1], v[40 + 2])
		+ MUL15(u[40 + 2], v[40 + 1])
		+ MUL15(u[40 + 3], v[40 + 0]);
	w[80 + 4] = MUL15(u[40 + 0], v[40 + 4])
		+ MUL15(u[40 + 1], v[40 + 3])
		+ MUL15(u[40 + 2], v[40 + 2])
		+ MUL15(u[40 + 3], v[40 + 1]);
		/* + MUL15(u[40 + 4], v[40 + 0]) */
	w[80 + 5] = MUL15(u[40 + 1], v[40 + 4])
		+ MUL15(u[40 + 2], v[40 + 3])
		+ MUL15(u[40 + 3], v[40 + 2])
		+ MUL15(u[40 + 4], v[40 + 1]);
	w[80 + 6] = MUL15(u[40 + 2], v[40 + 4])
		+ MUL15(u[40 + 3], v[40 + 3])
		+ MUL15(u[40 + 4], v[40 + 2]);
	w[80 + 7] = MUL15(u[40 + 3], v[40 + 4])
		+ MUL15(u[40 + 4], v[40 + 3]);
	w[80 + 8] = MUL15(u[40 + 4], v[40 + 4]);

	CPR(w, 80);

	w[80 + 4] += MUL15(u[40 + 4], v[40 + 0]);

	/*
	 * The products on 14-bit words in slots 6 and 7 yield values
	 * up to 5*(16382^2) each, and we need to subtract two such
	 * values from the higher word. We need the subtraction to fit
	 * in a _signed_ 32-bit integer, i.e. 31 bits + a sign bit.
	 * However, 10*(16382^2) does not fit. So we must perform a
	 * bit of reduction here.
	 */
	CPR(w, 60);
	CPR(w, 70);

	/*
	 * Recompose results.
	 */

	/* 0..1*0..1 into 0..3 */
	ZSUB2F(w, 8, w, 0, w, 2);
	ZSUB2F(w, 9, w, 1, w, 3);
	ZADDT(w, 1, w, 8);
	ZADDT(w, 2, w, 9);

	/* 2..3*2..3 into 4..7 */
	ZSUB2F(w, 10, w, 4, w, 6);
	ZSUB2F(w, 11, w, 5, w, 7);
	ZADDT(w, 5, w, 10);
	ZADDT(w, 6, w, 11);

	/* (0..1+2..3)*(0..1+2..3) into 12..15 */
	ZSUB2F(w, 16, w, 12, w, 14);
	ZSUB2F(w, 17, w, 13, w, 15);
	ZADDT(w, 13, w, 16);
	ZADDT(w, 14, w, 17);

	/* first-level recomposition */
	ZSUB2F(w, 12, w, 0, w, 4);
	ZSUB2F(w, 13, w, 1, w, 5);
	ZSUB2F(w, 14, w, 2, w, 6);
	ZSUB2F(w, 15, w, 3, w, 7);
	ZADDT(w, 2, w, 12);
	ZADDT(w, 3, w, 13);
	ZADDT(w, 4, w, 14);
	ZADDT(w, 5, w, 15);

	/*
	 * Perform carry propagation to bring all words down to 13 bits.
	 */
	cc = norm13(d, w, 40);
	d[39] += (cc << 13);

#undef ZADD
#undef ZADDT
#undef ZSUB2F
#undef CPR1
#undef CPR
}

#else

static void
mul20(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	uint32_t t[39];

	t[ 0] = MUL15(a[ 0], b[ 0]);
	t[ 1] = MUL15(a[ 0], b[ 1])
		+ MUL15(a[ 1], b[ 0]);
	t[ 2] = MUL15(a[ 0], b[ 2])
		+ MUL15(a[ 1], b[ 1])
		+ MUL15(a[ 2], b[ 0]);
	t[ 3] = MUL15(a[ 0], b[ 3])
		+ MUL15(a[ 1], b[ 2])
		+ MUL15(a[ 2], b[ 1])
		+ MUL15(a[ 3], b[ 0]);
	t[ 4] = MUL15(a[ 0], b[ 4])
		+ MUL15(a[ 1], b[ 3])
		+ MUL15(a[ 2], b[ 2])
		+ MUL15(a[ 3], b[ 1])
		+ MUL15(a[ 4], b[ 0]);
	t[ 5] = MUL15(a[ 0], b[ 5])
		+ MUL15(a[ 1], b[ 4])
		+ MUL15(a[ 2], b[ 3])
		+ MUL15(a[ 3], b[ 2])
		+ MUL15(a[ 4], b[ 1])
		+ MUL15(a[ 5], b[ 0]);
	t[ 6] = MUL15(a[ 0], b[ 6])
		+ MUL15(a[ 1], b[ 5])
		+ MUL15(a[ 2], b[ 4])
		+ MUL15(a[ 3], b[ 3])
		+ MUL15(a[ 4], b[ 2])
		+ MUL15(a[ 5], b[ 1])
		+ MUL15(a[ 6], b[ 0]);
	t[ 7] = MUL15(a[ 0], b[ 7])
		+ MUL15(a[ 1], b[ 6])
		+ MUL15(a[ 2], b[ 5])
		+ MUL15(a[ 3], b[ 4])
		+ MUL15(a[ 4], b[ 3])
		+ MUL15(a[ 5], b[ 2])
		+ MUL15(a[ 6], b[ 1])
		+ MUL15(a[ 7], b[ 0]);
	t[ 8] = MUL15(a[ 0], b[ 8])
		+ MUL15(a[ 1], b[ 7])
		+ MUL15(a[ 2], b[ 6])
		+ MUL15(a[ 3], b[ 5])
		+ MUL15(a[ 4], b[ 4])
		+ MUL15(a[ 5], b[ 3])
		+ MUL15(a[ 6], b[ 2])
		+ MUL15(a[ 7], b[ 1])
		+ MUL15(a[ 8], b[ 0]);
	t[ 9] = MUL15(a[ 0], b[ 9])
		+ MUL15(a[ 1], b[ 8])
		+ MUL15(a[ 2], b[ 7])
		+ MUL15(a[ 3], b[ 6])
		+ MUL15(a[ 4], b[ 5])
		+ MUL15(a[ 5], b[ 4])
		+ MUL15(a[ 6], b[ 3])
		+ MUL15(a[ 7], b[ 2])
		+ MUL15(a[ 8], b[ 1])
		+ MUL15(a[ 9], b[ 0]);
	t[10] = MUL15(a[ 0], b[10])
		+ MUL15(a[ 1], b[ 9])
		+ MUL15(a[ 2], b[ 8])
		+ MUL15(a[ 3], b[ 7])
		+ MUL15(a[ 4], b[ 6])
		+ MUL15(a[ 5], b[ 5])
		+ MUL15(a[ 6], b[ 4])
		+ MUL15(a[ 7], b[ 3])
		+ MUL15(a[ 8], b[ 2])
		+ MUL15(a[ 9], b[ 1])
		+ MUL15(a[10], b[ 0]);
	t[11] = MUL15(a[ 0], b[11])
		+ MUL15(a[ 1], b[10])
		+ MUL15(a[ 2], b[ 9])
		+ MUL15(a[ 3], b[ 8])
		+ MUL15(a[ 4], b[ 7])
		+ MUL15(a[ 5], b[ 6])
		+ MUL15(a[ 6], b[ 5])
		+ MUL15(a[ 7], b[ 4])
		+ MUL15(a[ 8], b[ 3])
		+ MUL15(a[ 9], b[ 2])
		+ MUL15(a[10], b[ 1])
		+ MUL15(a[11], b[ 0]);
	t[12] = MUL15(a[ 0], b[12])
		+ MUL15(a[ 1], b[11])
		+ MUL15(a[ 2], b[10])
		+ MUL15(a[ 3], b[ 9])
		+ MUL15(a[ 4], b[ 8])
		+ MUL15(a[ 5], b[ 7])
		+ MUL15(a[ 6], b[ 6])
		+ MUL15(a[ 7], b[ 5])
		+ MUL15(a[ 8], b[ 4])
		+ MUL15(a[ 9], b[ 3])
		+ MUL15(a[10], b[ 2])
		+ MUL15(a[11], b[ 1])
		+ MUL15(a[12], b[ 0]);
	t[13] = MUL15(a[ 0], b[13])
		+ MUL15(a[ 1], b[12])
		+ MUL15(a[ 2], b[11])
		+ MUL15(a[ 3], b[10])
		+ MUL15(a[ 4], b[ 9])
		+ MUL15(a[ 5], b[ 8])
		+ MUL15(a[ 6], b[ 7])
		+ MUL15(a[ 7], b[ 6])
		+ MUL15(a[ 8], b[ 5])
		+ MUL15(a[ 9], b[ 4])
		+ MUL15(a[10], b[ 3])
		+ MUL15(a[11], b[ 2])
		+ MUL15(a[12], b[ 1])
		+ MUL15(a[13], b[ 0]);
	t[14] = MUL15(a[ 0], b[14])
		+ MUL15(a[ 1], b[13])
		+ MUL15(a[ 2], b[12])
		+ MUL15(a[ 3], b[11])
		+ MUL15(a[ 4], b[10])
		+ MUL15(a[ 5], b[ 9])
		+ MUL15(a[ 6], b[ 8])
		+ MUL15(a[ 7], b[ 7])
		+ MUL15(a[ 8], b[ 6])
		+ MUL15(a[ 9], b[ 5])
		+ MUL15(a[10], b[ 4])
		+ MUL15(a[11], b[ 3])
		+ MUL15(a[12], b[ 2])
		+ MUL15(a[13], b[ 1])
		+ MUL15(a[14], b[ 0]);
	t[15] = MUL15(a[ 0], b[15])
		+ MUL15(a[ 1], b[14])
		+ MUL15(a[ 2], b[13])
		+ MUL15(a[ 3], b[12])
		+ MUL15(a[ 4], b[11])
		+ MUL15(a[ 5], b[10])
		+ MUL15(a[ 6], b[ 9])
		+ MUL15(a[ 7], b[ 8])
		+ MUL15(a[ 8], b[ 7])
		+ MUL15(a[ 9], b[ 6])
		+ MUL15(a[10], b[ 5])
		+ MUL15(a[11], b[ 4])
		+ MUL15(a[12], b[ 3])
		+ MUL15(a[13], b[ 2])
		+ MUL15(a[14], b[ 1])
		+ MUL15(a[15], b[ 0]);
	t[16] = MUL15(a[ 0], b[16])
		+ MUL15(a[ 1], b[15])
		+ MUL15(a[ 2], b[14])
		+ MUL15(a[ 3], b[13])
		+ MUL15(a[ 4], b[12])
		+ MUL15(a[ 5], b[11])
		+ MUL15(a[ 6], b[10])
		+ MUL15(a[ 7], b[ 9])
		+ MUL15(a[ 8], b[ 8])
		+ MUL15(a[ 9], b[ 7])
		+ MUL15(a[10], b[ 6])
		+ MUL15(a[11], b[ 5])
		+ MUL15(a[12], b[ 4])
		+ MUL15(a[13], b[ 3])
		+ MUL15(a[14], b[ 2])
		+ MUL15(a[15], b[ 1])
		+ MUL15(a[16], b[ 0]);
	t[17] = MUL15(a[ 0], b[17])
		+ MUL15(a[ 1], b[16])
		+ MUL15(a[ 2], b[15])
		+ MUL15(a[ 3], b[14])
		+ MUL15(a[ 4], b[13])
		+ MUL15(a[ 5], b[12])
		+ MUL15(a[ 6], b[11])
		+ MUL15(a[ 7], b[10])
		+ MUL15(a[ 8], b[ 9])
		+ MUL15(a[ 9], b[ 8])
		+ MUL15(a[10], b[ 7])
		+ MUL15(a[11], b[ 6])
		+ MUL15(a[12], b[ 5])
		+ MUL15(a[13], b[ 4])
		+ MUL15(a[14], b[ 3])
		+ MUL15(a[15], b[ 2])
		+ MUL15(a[16], b[ 1])
		+ MUL15(a[17], b[ 0]);
	t[18] = MUL15(a[ 0], b[18])
		+ MUL15(a[ 1], b[17])
		+ MUL15(a[ 2], b[16])
		+ MUL15(a[ 3], b[15])
		+ MUL15(a[ 4], b[14])
		+ MUL15(a[ 5], b[13])
		+ MUL15(a[ 6], b[12])
		+ MUL15(a[ 7], b[11])
		+ MUL15(a[ 8], b[10])
		+ MUL15(a[ 9], b[ 9])
		+ MUL15(a[10], b[ 8])
		+ MUL15(a[11], b[ 7])
		+ MUL15(a[12], b[ 6])
		+ MUL15(a[13], b[ 5])
		+ MUL15(a[14], b[ 4])
		+ MUL15(a[15], b[ 3])
		+ MUL15(a[16], b[ 2])
		+ MUL15(a[17], b[ 1])
		+ MUL15(a[18], b[ 0]);
	t[19] = MUL15(a[ 0], b[19])
		+ MUL15(a[ 1], b[18])
		+ MUL15(a[ 2], b[17])
		+ MUL15(a[ 3], b[16])
		+ MUL15(a[ 4], b[15])
		+ MUL15(a[ 5], b[14])
		+ MUL15(a[ 6], b[13])
		+ MUL15(a[ 7], b[12])
		+ MUL15(a[ 8], b[11])
		+ MUL15(a[ 9], b[10])
		+ MUL15(a[10], b[ 9])
		+ MUL15(a[11], b[ 8])
		+ MUL15(a[12], b[ 7])
		+ MUL15(a[13], b[ 6])
		+ MUL15(a[14], b[ 5])
		+ MUL15(a[15], b[ 4])
		+ MUL15(a[16], b[ 3])
		+ MUL15(a[17], b[ 2])
		+ MUL15(a[18], b[ 1])
		+ MUL15(a[19], b[ 0]);
	t[20] = MUL15(a[ 1], b[19])
		+ MUL15(a[ 2], b[18])
		+ MUL15(a[ 3], b[17])
		+ MUL15(a[ 4], b[16])
		+ MUL15(a[ 5], b[15])
		+ MUL15(a[ 6], b[14])
		+ MUL15(a[ 7], b[13])
		+ MUL15(a[ 8], b[12])
		+ MUL15(a[ 9], b[11])
		+ MUL15(a[10], b[10])
		+ MUL15(a[11], b[ 9])
		+ MUL15(a[12], b[ 8])
		+ MUL15(a[13], b[ 7])
		+ MUL15(a[14], b[ 6])
		+ MUL15(a[15], b[ 5])
		+ MUL15(a[16], b[ 4])
		+ MUL15(a[17], b[ 3])
		+ MUL15(a[18], b[ 2])
		+ MUL15(a[19], b[ 1]);
	t[21] = MUL15(a[ 2], b[19])
		+ MUL15(a[ 3], b[18])
		+ MUL15(a[ 4], b[17])
		+ MUL15(a[ 5], b[16])
		+ MUL15(a[ 6], b[15])
		+ MUL15(a[ 7], b[14])
		+ MUL15(a[ 8], b[13])
		+ MUL15(a[ 9], b[12])
		+ MUL15(a[10], b[11])
		+ MUL15(a[11], b[10])
		+ MUL15(a[12], b[ 9])
		+ MUL15(a[13], b[ 8])
		+ MUL15(a[14], b[ 7])
		+ MUL15(a[15], b[ 6])
		+ MUL15(a[16], b[ 5])
		+ MUL15(a[17], b[ 4])
		+ MUL15(a[18], b[ 3])
		+ MUL15(a[19], b[ 2]);
	t[22] = MUL15(a[ 3], b[19])
		+ MUL15(a[ 4], b[18])
		+ MUL15(a[ 5], b[17])
		+ MUL15(a[ 6], b[16])
		+ MUL15(a[ 7], b[15])
		+ MUL15(a[ 8], b[14])
		+ MUL15(a[ 9], b[13])
		+ MUL15(a[10], b[12])
		+ MUL15(a[11], b[11])
		+ MUL15(a[12], b[10])
		+ MUL15(a[13], b[ 9])
		+ MUL15(a[14], b[ 8])
		+ MUL15(a[15], b[ 7])
		+ MUL15(a[16], b[ 6])
		+ MUL15(a[17], b[ 5])
		+ MUL15(a[18], b[ 4])
		+ MUL15(a[19], b[ 3]);
	t[23] = MUL15(a[ 4], b[19])
		+ MUL15(a[ 5], b[18])
		+ MUL15(a[ 6], b[17])
		+ MUL15(a[ 7], b[16])
		+ MUL15(a[ 8], b[15])
		+ MUL15(a[ 9], b[14])
		+ MUL15(a[10], b[13])
		+ MUL15(a[11], b[12])
		+ MUL15(a[12], b[11])
		+ MUL15(a[13], b[10])
		+ MUL15(a[14], b[ 9])
		+ MUL15(a[15], b[ 8])
		+ MUL15(a[16], b[ 7])
		+ MUL15(a[17], b[ 6])
		+ MUL15(a[18], b[ 5])
		+ MUL15(a[19], b[ 4]);
	t[24] = MUL15(a[ 5], b[19])
		+ MUL15(a[ 6], b[18])
		+ MUL15(a[ 7], b[17])
		+ MUL15(a[ 8], b[16])
		+ MUL15(a[ 9], b[15])
		+ MUL15(a[10], b[14])
		+ MUL15(a[11], b[13])
		+ MUL15(a[12], b[12])
		+ MUL15(a[13], b[11])
		+ MUL15(a[14], b[10])
		+ MUL15(a[15], b[ 9])
		+ MUL15(a[16], b[ 8])
		+ MUL15(a[17], b[ 7])
		+ MUL15(a[18], b[ 6])
		+ MUL15(a[19], b[ 5]);
	t[25] = MUL15(a[ 6], b[19])
		+ MUL15(a[ 7], b[18])
		+ MUL15(a[ 8], b[17])
		+ MUL15(a[ 9], b[16])
		+ MUL15(a[10], b[15])
		+ MUL15(a[11], b[14])
		+ MUL15(a[12], b[13])
		+ MUL15(a[13], b[12])
		+ MUL15(a[14], b[11])
		+ MUL15(a[15], b[10])
		+ MUL15(a[16], b[ 9])
		+ MUL15(a[17], b[ 8])
		+ MUL15(a[18], b[ 7])
		+ MUL15(a[19], b[ 6]);
	t[26] = MUL15(a[ 7], b[19])
		+ MUL15(a[ 8], b[18])
		+ MUL15(a[ 9], b[17])
		+ MUL15(a[10], b[16])
		+ MUL15(a[11], b[15])
		+ MUL15(a[12], b[14])
		+ MUL15(a[13], b[13])
		+ MUL15(a[14], b[12])
		+ MUL15(a[15], b[11])
		+ MUL15(a[16], b[10])
		+ MUL15(a[17], b[ 9])
		+ MUL15(a[18], b[ 8])
		+ MUL15(a[19], b[ 7]);
	t[27] = MUL15(a[ 8], b[19])
		+ MUL15(a[ 9], b[18])
		+ MUL15(a[10], b[17])
		+ MUL15(a[11], b[16])
		+ MUL15(a[12], b[15])
		+ MUL15(a[13], b[14])
		+ MUL15(a[14], b[13])
		+ MUL15(a[15], b[12])
		+ MUL15(a[16], b[11])
		+ MUL15(a[17], b[10])
		+ MUL15(a[18], b[ 9])
		+ MUL15(a[19], b[ 8]);
	t[28] = MUL15(a[ 9], b[19])
		+ MUL15(a[10], b[18])
		+ MUL15(a[11], b[17])
		+ MUL15(a[12], b[16])
		+ MUL15(a[13], b[15])
		+ MUL15(a[14], b[14])
		+ MUL15(a[15], b[13])
		+ MUL15(a[16], b[12])
		+ MUL15(a[17], b[11])
		+ MUL15(a[18], b[10])
		+ MUL15(a[19], b[ 9]);
	t[29] = MUL15(a[10], b[19])
		+ MUL15(a[11], b[18])
		+ MUL15(a[12], b[17])
		+ MUL15(a[13], b[16])
		+ MUL15(a[14], b[15])
		+ MUL15(a[15], b[14])
		+ MUL15(a[16], b[13])
		+ MUL15(a[17], b[12])
		+ MUL15(a[18], b[11])
		+ MUL15(a[19], b[10]);
	t[30] = MUL15(a[11], b[19])
		+ MUL15(a[12], b[18])
		+ MUL15(a[13], b[17])
		+ MUL15(a[14], b[16])
		+ MUL15(a[15], b[15])
		+ MUL15(a[16], b[14])
		+ MUL15(a[17], b[13])
		+ MUL15(a[18], b[12])
		+ MUL15(a[19], b[11]);
	t[31] = MUL15(a[12], b[19])
		+ MUL15(a[13], b[18])
		+ MUL15(a[14], b[17])
		+ MUL15(a[15], b[16])
		+ MUL15(a[16], b[15])
		+ MUL15(a[17], b[14])
		+ MUL15(a[18], b[13])
		+ MUL15(a[19], b[12]);
	t[32] = MUL15(a[13], b[19])
		+ MUL15(a[14], b[18])
		+ MUL15(a[15], b[17])
		+ MUL15(a[16], b[16])
		+ MUL15(a[17], b[15])
		+ MUL15(a[18], b[14])
		+ MUL15(a[19], b[13]);
	t[33] = MUL15(a[14], b[19])
		+ MUL15(a[15], b[18])
		+ MUL15(a[16], b[17])
		+ MUL15(a[17], b[16])
		+ MUL15(a[18], b[15])
		+ MUL15(a[19], b[14]);
	t[34] = MUL15(a[15], b[19])
		+ MUL15(a[16], b[18])
		+ MUL15(a[17], b[17])
		+ MUL15(a[18], b[16])
		+ MUL15(a[19], b[15]);
	t[35] = MUL15(a[16], b[19])
		+ MUL15(a[17], b[18])
		+ MUL15(a[18], b[17])
		+ MUL15(a[19], b[16]);
	t[36] = MUL15(a[17], b[19])
		+ MUL15(a[18], b[18])
		+ MUL15(a[19], b[17]);
	t[37] = MUL15(a[18], b[19])
		+ MUL15(a[19], b[18]);
	t[38] = MUL15(a[19], b[19]);
	d[39] = norm13(d, t, 39);
}

#endif

/*
 * Modulus for field F256 (field for point coordinates in curve P-256).
 */
static const uint32_t F256[] = {
	0x1FFF, 0x1FFF, 0x1FFF, 0x1FFF, 0x1FFF, 0x1FFF, 0x1FFF, 0x001F,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0400, 0x0000,
	0x0000, 0x1FF8, 0x1FFF, 0x01FF
};

/*
 * The 'b' curve equation coefficient for P-256.
 */
static const uint32_t P256_B[] = {
	0x004B, 0x1E93, 0x0F89, 0x1C78, 0x03BC, 0x187B, 0x114E, 0x1619,
	0x1D06, 0x0328, 0x01AF, 0x0D31, 0x1557, 0x15DE, 0x1ECF, 0x127C,
	0x0A3A, 0x0EC5, 0x118D, 0x00B5
};

/*
 * Perform a "short reduction" in field F256 (field for curve P-256).
 * The source value should be less than 262 bits; on output, it will
 * be at most 257 bits, and less than twice the modulus.
 */
static void
reduce_f256(uint32_t *d)
{
	uint32_t x;

	x = d[19] >> 9;
	d[19] &= 0x01FF;
	d[17] += x << 3;
	d[14] -= x << 10;
	d[7] -= x << 5;
	d[0] += x;
	norm13(d, d, 20);
}

/*
 * Perform a "final reduction" in field F256 (field for curve P-256).
 * The source value must be less than twice the modulus. If the value
 * is not lower than the modulus, then the modulus is subtracted and
 * this function returns 1; otherwise, it leaves it untouched and it
 * returns 0.
 */
static uint32_t
reduce_final_f256(uint32_t *d)
{
	uint32_t t[20];
	uint32_t cc;
	int i;

	memcpy(t, d, sizeof t);
	cc = 0;
	for (i = 0; i < 20; i ++) {
		uint32_t w;

		w = t[i] - F256[i] - cc;
		cc = w >> 31;
		t[i] = w & 0x1FFF;
	}
	cc ^= 1;
	CCOPY(cc, d, t, sizeof t);
	return cc;
}

/*
 * Perform a multiplication of two integers modulo
 * 2^256-2^224+2^192+2^96-1 (for NIST curve P-256). Operands are arrays
 * of 20 words, each containing 13 bits of data, in little-endian order.
 * On input, upper word may be up to 15 bits (hence value up to 2^262-1);
 * on output, value fits on 257 bits and is lower than twice the modulus.
 */
static void
mul_f256(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	uint32_t t[40], cc;
	int i;

	/*
	 * Compute raw multiplication. All result words fit in 13 bits
	 * each.
	 */
	mul20(t, a, b);

	/*
	 * Modular reduction: each high word in added/subtracted where
	 * necessary.
	 *
	 * The modulus is:
	 *    p = 2^256 - 2^224 + 2^192 + 2^96 - 1
	 * Therefore:
	 *    2^256 = 2^224 - 2^192 - 2^96 + 1 mod p
	 *
	 * For a word x at bit offset n (n >= 256), we have:
	 *    x*2^n = x*2^(n-32) - x*2^(n-64)
	 *            - x*2^(n - 160) + x*2^(n-256) mod p
	 *
	 * Thus, we can nullify the high word if we reinject it at some
	 * proper emplacements.
	 */
	for (i = 39; i >= 20; i --) {
		uint32_t x;

		x = t[i];
		t[i - 2] += ARSH(x, 6);
		t[i - 3] += (x << 7) & 0x1FFF;
		t[i - 4] -= ARSH(x, 12);
		t[i - 5] -= (x << 1) & 0x1FFF;
		t[i - 12] -= ARSH(x, 4);
		t[i - 13] -= (x << 9) & 0x1FFF;
		t[i - 19] += ARSH(x, 9);
		t[i - 20] += (x << 4) & 0x1FFF;
	}

	/*
	 * Propagate carries. Since the operation above really is a
	 * truncature, followed by the addition of nonnegative values,
	 * the result will be positive. Moreover, the carry cannot
	 * exceed 5 bits (we performed 20 additions with values smaller
	 * than 256 bits).
	 */
	cc = norm13(t, t, 20);

	/*
	 * Perform modular reduction again for the bits beyond 256 (the carry
	 * and the bits 256..259). This time, we can simply inject full
	 * word values.
	 */
	cc = (cc << 4) | (t[19] >> 9);
	t[19] &= 0x01FF;
	t[17] += cc << 3;
	t[14] -= cc << 10;
	t[7] -= cc << 5;
	t[0] += cc;
	norm13(d, t, 20);
}

/*
 * Jacobian coordinates for a point in P-256: affine coordinates (X,Y)
 * are such that:
 *   X = x / z^2
 *   Y = y / z^3
 * For the point at infinity, z = 0.
 * Each point thus admits many possible representations.
 *
 * Coordinates are represented in arrays of 32-bit integers, each holding
 * 13 bits of data. Values may also be slightly greater than the modulus,
 * but they will always be lower than twice the modulus.
 */
typedef struct {
	uint32_t x[20];
	uint32_t y[20];
	uint32_t z[20];
} p256_jacobian;

/*
 * Convert a point to affine coordinates:
 *  - If the point is the point at infinity, then all three coordinates
 *    are set to 0.
 *  - Otherwise, the 'z' coordinate is set to 1, and the 'x' and 'y'
 *    coordinates are the 'X' and 'Y' affine coordinates.
 * The coordinates are guaranteed to be lower than the modulus.
 */
static void
p256_to_affine(p256_jacobian *P)
{
	uint32_t t1[20], t2[20];
	int i;

	/*
	 * Invert z with a modular exponentiation: the modulus is
	 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1, and the exponent is
	 * p-2. Exponent bit pattern (from high to low) is:
	 *  - 32 bits of value 1
	 *  - 31 bits of value 0
	 *  - 1 bit of value 1
	 *  - 96 bits of value 0
	 *  - 94 bits of value 1
	 *  - 1 bit of value 0
	 *  - 1 bit of value 1
	 * Thus, we precompute z^(2^31-1) to speed things up.
	 *
	 * If z = 0 (point at infinity) then the modular exponentiation
	 * will yield 0, which leads to the expected result (all three
	 * coordinates set to 0).
	 */

	/*
	 * A simple square-and-multiply for z^(2^31-1). We could save about
	 * two dozen multiplications here with an addition chain, but
	 * this would require a bit more code, and extra stack buffers.
	 */
	memcpy(t1, P->z, sizeof P->z);
	for (i = 0; i < 30; i ++) {
		mul_f256(t1, t1, t1);
		mul_f256(t1, t1, P->z);
	}

	/*
	 * Square-and-multiply. Apart from the squarings, we have a few
	 * multiplications to set bits to 1; we multiply by the original z
	 * for setting 1 bit, and by t1 for setting 31 bits.
	 */
	memcpy(t2, P->z, sizeof P->z);
	for (i = 1; i < 256; i ++) {
		mul_f256(t2, t2, t2);
		switch (i) {
		case 31:
		case 190:
		case 221:
		case 252:
			mul_f256(t2, t2, t1);
			break;
		case 63:
		case 253:
		case 255:
			mul_f256(t2, t2, P->z);
			break;
		}
	}

	/*
	 * Now that we have 1/z, multiply x by 1/z^2 and y by 1/z^3.
	 */
	mul_f256(t1, t2, t2);
	mul_f256(P->x, t1, P->x);
	mul_f256(t1, t1, t2);
	mul_f256(P->y, t1, P->y);
	reduce_final_f256(P->x);
	reduce_final_f256(P->y);

	/*
	 * Multiply z by 1/z. If z = 0, then this will yield 0, otherwise
	 * this will set z to 1.
	 */
	mul_f256(P->z, P->z, t2);
	reduce_final_f256(P->z);
}

/*
 * Double a point in P-256. This function works for all valid points,
 * including the point at infinity.
 */
static void
p256_double(p256_jacobian *Q)
{
	/*
	 * Doubling formulas are:
	 *
	 *   s = 4*x*y^2
	 *   m = 3*(x + z^2)*(x - z^2)
	 *   x' = m^2 - 2*s
	 *   y' = m*(s - x') - 8*y^4
	 *   z' = 2*y*z
	 *
	 * These formulas work for all points, including points of order 2
	 * and points at infinity:
	 *   - If y = 0 then z' = 0. But there is no such point in P-256
	 *     anyway.
	 *   - If z = 0 then z' = 0.
	 */
	uint32_t t1[20], t2[20], t3[20], t4[20];
	int i;

	/*
	 * Compute z^2 in t1.
	 */
	mul_f256(t1, Q->z, Q->z);

	/*
	 * Compute x-z^2 in t2 and x+z^2 in t1.
	 */
	for (i = 0; i < 20; i ++) {
		t2[i] = (F256[i] << 1) + Q->x[i] - t1[i];
		t1[i] += Q->x[i];
	}
	norm13(t1, t1, 20);
	norm13(t2, t2, 20);

	/*
	 * Compute 3*(x+z^2)*(x-z^2) in t1.
	 */
	mul_f256(t3, t1, t2);
	for (i = 0; i < 20; i ++) {
		t1[i] = MUL15(3, t3[i]);
	}
	norm13(t1, t1, 20);

	/*
	 * Compute 4*x*y^2 (in t2) and 2*y^2 (in t3).
	 */
	mul_f256(t3, Q->y, Q->y);
	for (i = 0; i < 20; i ++) {
		t3[i] <<= 1;
	}
	norm13(t3, t3, 20);
	mul_f256(t2, Q->x, t3);
	for (i = 0; i < 20; i ++) {
		t2[i] <<= 1;
	}
	norm13(t2, t2, 20);
	reduce_f256(t2);

	/*
	 * Compute x' = m^2 - 2*s.
	 */
	mul_f256(Q->x, t1, t1);
	for (i = 0; i < 20; i ++) {
		Q->x[i] += (F256[i] << 2) - (t2[i] << 1);
	}
	norm13(Q->x, Q->x, 20);
	reduce_f256(Q->x);

	/*
	 * Compute z' = 2*y*z.
	 */
	mul_f256(t4, Q->y, Q->z);
	for (i = 0; i < 20; i ++) {
		Q->z[i] = t4[i] << 1;
	}
	norm13(Q->z, Q->z, 20);
	reduce_f256(Q->z);

	/*
	 * Compute y' = m*(s - x') - 8*y^4. Note that we already have
	 * 2*y^2 in t3.
	 */
	for (i = 0; i < 20; i ++) {
		t2[i] += (F256[i] << 1) - Q->x[i];
	}
	norm13(t2, t2, 20);
	mul_f256(Q->y, t1, t2);
	mul_f256(t4, t3, t3);
	for (i = 0; i < 20; i ++) {
		Q->y[i] += (F256[i] << 2) - (t4[i] << 1);
	}
	norm13(Q->y, Q->y, 20);
	reduce_f256(Q->y);
}

/*
 * Add point P2 to point P1.
 *
 * This function computes the wrong result in the following cases:
 *
 *   - If P1 == 0 but P2 != 0
 *   - If P1 != 0 but P2 == 0
 *   - If P1 == P2
 *
 * In all three cases, P1 is set to the point at infinity.
 *
 * Returned value is 0 if one of the following occurs:
 *
 *   - P1 and P2 have the same Y coordinate
 *   - P1 == 0 and P2 == 0
 *   - The Y coordinate of one of the points is 0 and the other point is
 *     the point at infinity.
 *
 * The third case cannot actually happen with valid points, since a point
 * with Y == 0 is a point of order 2, and there is no point of order 2 on
 * curve P-256.
 *
 * Therefore, assuming that P1 != 0 and P2 != 0 on input, then the caller
 * can apply the following:
 *
 *   - If the result is not the point at infinity, then it is correct.
 *   - Otherwise, if the returned value is 1, then this is a case of
 *     P1+P2 == 0, so the result is indeed the point at infinity.
 *   - Otherwise, P1 == P2, so a "double" operation should have been
 *     performed.
 */
static uint32_t
p256_add(p256_jacobian *P1, const p256_jacobian *P2)
{
	/*
	 * Addtions formulas are:
	 *
	 *   u1 = x1 * z2^2
	 *   u2 = x2 * z1^2
	 *   s1 = y1 * z2^3
	 *   s2 = y2 * z1^3
	 *   h = u2 - u1
	 *   r = s2 - s1
	 *   x3 = r^2 - h^3 - 2 * u1 * h^2
	 *   y3 = r * (u1 * h^2 - x3) - s1 * h^3
	 *   z3 = h * z1 * z2
	 */
	uint32_t t1[20], t2[20], t3[20], t4[20], t5[20], t6[20], t7[20];
	uint32_t ret;
	int i;

	/*
	 * Compute u1 = x1*z2^2 (in t1) and s1 = y1*z2^3 (in t3).
	 */
	mul_f256(t3, P2->z, P2->z);
	mul_f256(t1, P1->x, t3);
	mul_f256(t4, P2->z, t3);
	mul_f256(t3, P1->y, t4);

	/*
	 * Compute u2 = x2*z1^2 (in t2) and s2 = y2*z1^3 (in t4).
	 */
	mul_f256(t4, P1->z, P1->z);
	mul_f256(t2, P2->x, t4);
	mul_f256(t5, P1->z, t4);
	mul_f256(t4, P2->y, t5);

	/*
	 * Compute h = h2 - u1 (in t2) and r = s2 - s1 (in t4).
	 * We need to test whether r is zero, so we will do some extra
	 * reduce.
	 */
	for (i = 0; i < 20; i ++) {
		t2[i] += (F256[i] << 1) - t1[i];
		t4[i] += (F256[i] << 1) - t3[i];
	}
	norm13(t2, t2, 20);
	norm13(t4, t4, 20);
	reduce_f256(t4);
	reduce_final_f256(t4);
	ret = 0;
	for (i = 0; i < 20; i ++) {
		ret |= t4[i];
	}
	ret = (ret | -ret) >> 31;

	/*
	 * Compute u1*h^2 (in t6) and h^3 (in t5);
	 */
	mul_f256(t7, t2, t2);
	mul_f256(t6, t1, t7);
	mul_f256(t5, t7, t2);

	/*
	 * Compute x3 = r^2 - h^3 - 2*u1*h^2.
	 */
	mul_f256(P1->x, t4, t4);
	for (i = 0; i < 20; i ++) {
		P1->x[i] += (F256[i] << 3) - t5[i] - (t6[i] << 1);
	}
	norm13(P1->x, P1->x, 20);
	reduce_f256(P1->x);

	/*
	 * Compute y3 = r*(u1*h^2 - x3) - s1*h^3.
	 */
	for (i = 0; i < 20; i ++) {
		t6[i] += (F256[i] << 1) - P1->x[i];
	}
	norm13(t6, t6, 20);
	mul_f256(P1->y, t4, t6);
	mul_f256(t1, t5, t3);
	for (i = 0; i < 20; i ++) {
		P1->y[i] += (F256[i] << 1) - t1[i];
	}
	norm13(P1->y, P1->y, 20);
	reduce_f256(P1->y);

	/*
	 * Compute z3 = h*z1*z2.
	 */
	mul_f256(t1, P1->z, P2->z);
	mul_f256(P1->z, t1, t2);

	return ret;
}

/*
 * Decode a P-256 point. This function does not support the point at
 * infinity. Returned value is 0 if the point is invalid, 1 otherwise.
 */
static uint32_t
p256_decode(p256_jacobian *P, const void *src, size_t len)
{
	const unsigned char *buf;
	uint32_t tx[20], ty[20], t1[20], t2[20];
	uint32_t bad;
	int i;

	if (len != 65) {
		return 0;
	}
	buf = src;

	/*
	 * First byte must be 0x04 (uncompressed format). We could support
	 * "hybrid format" (first byte is 0x06 or 0x07, and encodes the
	 * least significant bit of the Y coordinate), but it is explicitly
	 * forbidden by RFC 5480 (section 2.2).
	 */
	bad = NEQ(buf[0], 0x04);

	/*
	 * Decode the coordinates, and check that they are both lower
	 * than the modulus.
	 */
	tx[19] = be8_to_le13(tx, buf + 1, 32);
	ty[19] = be8_to_le13(ty, buf + 33, 32);
	bad |= reduce_final_f256(tx);
	bad |= reduce_final_f256(ty);

	/*
	 * Check curve equation.
	 */
	mul_f256(t1, tx, tx);
	mul_f256(t1, tx, t1);
	mul_f256(t2, ty, ty);
	for (i = 0; i < 20; i ++) {
		t1[i] += (F256[i] << 3) - MUL15(3, tx[i]) + P256_B[i] - t2[i];
	}
	norm13(t1, t1, 20);
	reduce_f256(t1);
	reduce_final_f256(t1);
	for (i = 0; i < 20; i ++) {
		bad |= t1[i];
	}

	/*
	 * Copy coordinates to the point structure.
	 */
	memcpy(P->x, tx, sizeof tx);
	memcpy(P->y, ty, sizeof ty);
	memset(P->z, 0, sizeof P->z);
	P->z[0] = 1;
	return NEQ(bad, 0) ^ 1;
}

/*
 * Encode a point into a buffer. This function assumes that the point is
 * valid, in affine coordinates, and not the point at infinity.
 */
static void
p256_encode(void *dst, const p256_jacobian *P)
{
	unsigned char *buf;

	buf = dst;
	buf[0] = 0x04;
	le13_to_be8(buf + 1, 32, P->x);
	le13_to_be8(buf + 33, 32, P->y);
}

/*
 * Multiply a curve point by an integer. The integer is assumed to be
 * lower than the curve order, and the base point must not be the point
 * at infinity.
 */
static void
p256_mul(p256_jacobian *P, const unsigned char *x, size_t xlen)
{
	/*
	 * qz is a flag that is initially 1, and remains equal to 1
	 * as long as the point is the point at infinity.
	 *
	 * We use a 2-bit window to handle multiplier bits by pairs.
	 * The precomputed window really is the points P2 and P3.
	 */
	uint32_t qz;
	p256_jacobian P2, P3, Q, T, U;

	/*
	 * Compute window values.
	 */
	P2 = *P;
	p256_double(&P2);
	P3 = *P;
	p256_add(&P3, &P2);

	/*
	 * We start with Q = 0. We process multiplier bits 2 by 2.
	 */
	memset(&Q, 0, sizeof Q);
	qz = 1;
	while (xlen -- > 0) {
		int k;

		for (k = 6; k >= 0; k -= 2) {
			uint32_t bits;
			uint32_t bnz;

			p256_double(&Q);
			p256_double(&Q);
			T = *P;
			U = Q;
			bits = (*x >> k) & (uint32_t)3;
			bnz = NEQ(bits, 0);
			CCOPY(EQ(bits, 2), &T, &P2, sizeof T);
			CCOPY(EQ(bits, 3), &T, &P3, sizeof T);
			p256_add(&U, &T);
			CCOPY(bnz & qz, &Q, &T, sizeof Q);
			CCOPY(bnz & ~qz, &Q, &U, sizeof Q);
			qz &= ~bnz;
		}
		x ++;
	}
	*P = Q;
}

static const unsigned char P256_G[] = {
	0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8,
	0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
	0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
	0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
	0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B,
	0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
	0x68, 0x37, 0xBF, 0x51, 0xF5
};

static const unsigned char P256_N[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD,
	0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
	0x25, 0x51
};

static const unsigned char *
api_generator(int curve, size_t *len)
{
	(void)curve;
	*len = sizeof P256_G;
	return P256_G;
}

static const unsigned char *
api_order(int curve, size_t *len)
{
	(void)curve;
	*len = sizeof P256_N;
	return P256_N;
}

static uint32_t
api_mul(unsigned char *G, size_t Glen,
	const unsigned char *x, size_t xlen, int curve)
{
	uint32_t r;
	p256_jacobian P;

	(void)curve;
	r = p256_decode(&P, G, Glen);
	p256_mul(&P, x, xlen);
	if (Glen >= 65) {
		p256_to_affine(&P);
		p256_encode(G, &P);
	}
	return r;
}

static uint32_t
api_muladd(unsigned char *A, const unsigned char *B, size_t len,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen, int curve)
{
	p256_jacobian P, Q;
	uint32_t r, t, z;
	int i;

	(void)curve;
	r = p256_decode(&P, A, len);
	r &= p256_decode(&Q, B, len);
	p256_mul(&P, x, xlen);
	p256_mul(&Q, y, ylen);

	/*
	 * The final addition may fail in case both points are equal.
	 */
	t = p256_add(&P, &Q);
	reduce_final_f256(P.z);
	z = 0;
	for (i = 0; i < 20; i ++) {
		z |= P.z[i];
	}
	z = EQ(z, 0);
	p256_double(&Q);

	/*
	 * If z is 1 then either P+Q = 0 (t = 1) or P = Q (t = 0). So we
	 * have the following:
	 *
	 *   z = 0, t = 0   return P (normal addition)
	 *   z = 0, t = 1   return P (normal addition)
	 *   z = 1, t = 0   return Q (a 'double' case)
	 *   z = 1, t = 1   report an error (P+Q = 0)
	 */
	CCOPY(z & ~t, &P, &Q, sizeof Q);
	p256_to_affine(&P);
	p256_encode(A, &P);
	r &= ~(z & t);
	return r;
}

/* see bearssl_ec.h */
const br_ec_impl br_ec_p256_i15 = {
	(uint32_t)0x00800000,
	&api_generator,
	&api_order,
	&api_mul,
	&api_muladd
};
