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
 * This file contains the core "big integer" functions for the i15
 * implementation, that represents integers as sequences of 15-bit
 * words.
 */

/* see inner.h */
uint32_t
br_i15_iszero(const uint16_t *x)
{
	uint32_t z;
	size_t u;

	z = 0;
	for (u = (x[0] + 15) >> 4; u > 0; u --) {
		z |= x[u];
	}
	return ~(z | -z) >> 31;
}

/* see inner.h */
uint16_t
br_i15_ninv15(uint16_t x)
{
	uint32_t y;

	y = 2 - x;
	y = MUL15(y, 2 - MUL15(x, y));
	y = MUL15(y, 2 - MUL15(x, y));
	y = MUL15(y, 2 - MUL15(x, y));
	return MUX(x & 1, -y, 0) & 0x7FFF;
}

/* see inner.h */
uint32_t
br_i15_add(uint16_t *a, const uint16_t *b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 31) >> 4;
	for (u = 1; u < m; u ++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw + bw + cc;
		cc = naw >> 15;
		a[u] = MUX(ctl, naw & 0x7FFF, aw);
	}
	return cc;
}

/* see inner.h */
uint32_t
br_i15_sub(uint16_t *a, const uint16_t *b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 31) >> 4;
	for (u = 1; u < m; u ++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw - bw - cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & 0x7FFF, aw);
	}
	return cc;
}

/*
 * Constant-time division. The divisor must not be larger than 16 bits,
 * and the quotient must fit on 17 bits.
 */
static uint32_t
divrem16(uint32_t x, uint32_t d, uint32_t *r)
{
	int i;
	uint32_t q;

	q = 0;
	d <<= 16;
	for (i = 16; i >= 0; i --) {
		uint32_t ctl;

		ctl = LE(d, x);
		q |= ctl << i;
		x -= (-ctl) & d;
		d >>= 1;
	}
	if (r != NULL) {
		*r = x;
	}
	return q;
}

/* see inner.h */
void
br_i15_muladd_small(uint16_t *x, uint16_t z, const uint16_t *m)
{
	/*
	 * Constant-time: we accept to leak the exact bit length of the
	 * modulus m.
	 */
	unsigned m_bitlen, mblr;
	size_t u, mlen;
	uint32_t hi, a0, a, b, q;
	uint32_t cc, tb, over, under;

	/*
	 * Simple case: the modulus fits on one word.
	 */
	m_bitlen = m[0];
	if (m_bitlen == 0) {
		return;
	}
	if (m_bitlen <= 15) {
		uint32_t rem;

		divrem16(((uint32_t)x[1] << 15) | z, m[1], &rem);
		x[1] = rem;
		return;
	}
	mlen = (m_bitlen + 15) >> 4;
	mblr = m_bitlen & 15;

	/*
	 * Principle: we estimate the quotient (x*2^15+z)/m by
	 * doing a 30/15 division with the high words.
	 *
	 * Let:
	 *   w = 2^15
	 *   a = (w*a0 + a1) * w^N + a2
	 *   b = b0 * w^N + b2
	 * such that:
	 *   0 <= a0 < w
	 *   0 <= a1 < w
	 *   0 <= a2 < w^N
	 *   w/2 <= b0 < w
	 *   0 <= b2 < w^N
	 *   a < w*b
	 * I.e. the two top words of a are a0:a1, the top word of b is
	 * b0, we ensured that b0 is "full" (high bit set), and a is
	 * such that the quotient q = a/b fits on one word (0 <= q < w).
	 *
	 * If a = b*q + r (with 0 <= r < q), then we can estimate q by
	 * using a division on the top words:
	 *   a0*w + a1 = b0*u + v (with 0 <= v < b0)
	 * Then the following holds:
	 *   0 <= u <= w
	 *   u-2 <= q <= u
	 */
	hi = x[mlen];
	if (mblr == 0) {
		a0 = x[mlen];
		memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
		x[1] = z;
		a = (a0 << 15) + x[mlen];
		b = m[mlen];
	} else {
		a0 = (x[mlen] << (15 - mblr)) | (x[mlen - 1] >> mblr);
		memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
		x[1] = z;
		a = (a0 << 15) | (((x[mlen] << (15 - mblr))
			| (x[mlen - 1] >> mblr)) & 0x7FFF);
		b = (m[mlen] << (15 - mblr)) | (m[mlen - 1] >> mblr);
	}
	q = divrem16(a, b, NULL);

	/*
	 * We computed an estimate for q, but the real one may be q,
	 * q-1 or q-2; moreover, the division may have returned a value
	 * 8000 or even 8001 if the two high words were identical, and
	 * we want to avoid values beyond 7FFF. We thus adjust q so
	 * that the "true" multiplier will be q+1, q or q-1, and q is
	 * in the 0000..7FFF range.
	 */
	q = MUX(EQ(b, a0), 0x7FFF, q - 1 + ((q - 1) >> 31));

	/*
	 * We subtract q*m from x (x has an extra high word of value 'hi').
	 * Since q may be off by 1 (in either direction), we may have to
	 * add or subtract m afterwards.
	 *
	 * The 'tb' flag will be true (1) at the end of the loop if the
	 * result is greater than or equal to the modulus (not counting
	 * 'hi' or the carry).
	 */
	cc = 0;
	tb = 1;
	for (u = 1; u <= mlen; u ++) {
		uint32_t mw, zl, xw, nxw;

		mw = m[u];
		zl = MUL15(mw, q) + cc;
		cc = zl >> 15;
		zl &= 0x7FFF;
		xw = x[u];
		nxw = xw - zl;
		cc += nxw >> 31;
		nxw &= 0x7FFF;
		x[u] = nxw;
		tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
	}

	/*
	 * If we underestimated q, then either cc < hi (one extra bit
	 * beyond the top array word), or cc == hi and tb is true (no
	 * extra bit, but the result is not lower than the modulus).
	 *
	 * If we overestimated q, then cc > hi.
	 */
	over = GT(cc, hi);
	under = ~over & (tb | LT(cc, hi));
	br_i15_add(x, m, over);
	br_i15_sub(x, m, under);
}

/* see inner.h */
void
br_i15_montymul(uint16_t *d, const uint16_t *x, const uint16_t *y,
	const uint16_t *m, uint16_t m0i)
{
	size_t len, len4, u, v;
	uint32_t dh;

	len = (m[0] + 15) >> 4;
	len4 = len & ~(size_t)3;
	br_i15_zero(d, m[0]);
	dh = 0;
	for (u = 0; u < len; u ++) {
		uint32_t f, xu, r, zh;

		xu = x[u + 1];
		f = MUL15(d[1] + MUL15(x[u + 1], y[1]), m0i) & 0x7FFF;

		r = 0;
		for (v = 0; v < len4; v += 4) {
			uint32_t z;

			z = d[v + 1] + MUL15(xu, y[v + 1])
				+ MUL15(f, m[v + 1]) + r;
			r = z >> 15;
			d[v + 0] = z & 0x7FFF;
			z = d[v + 2] + MUL15(xu, y[v + 2])
				+ MUL15(f, m[v + 2]) + r;
			r = z >> 15;
			d[v + 1] = z & 0x7FFF;
			z = d[v + 3] + MUL15(xu, y[v + 3])
				+ MUL15(f, m[v + 3]) + r;
			r = z >> 15;
			d[v + 2] = z & 0x7FFF;
			z = d[v + 4] + MUL15(xu, y[v + 4])
				+ MUL15(f, m[v + 4]) + r;
			r = z >> 15;
			d[v + 3] = z & 0x7FFF;
		}
		for (; v < len; v ++) {
			uint32_t z;

			z = d[v + 1] + MUL15(xu, y[v + 1])
				+ MUL15(f, m[v + 1]) + r;
			r = z >> 15;
			d[v + 0] = z & 0x7FFF;
		}

		zh = dh + r;
		d[len] = zh & 0x7FFF;
		dh = zh >> 31;
	}

	/*
	 * Restore the bit length (it was overwritten in the loop above).
	 */
	d[0] = m[0];

	/*
	 * d[] may be greater than m[], but it is still lower than twice
	 * the modulus.
	 */
	br_i15_sub(d, m, NEQ(dh, 0) | NOT(br_i15_sub(d, m, 0)));
}

/* see inner.h */
void
br_i15_to_monty(uint16_t *x, const uint16_t *m)
{
	unsigned k;

	for (k = (m[0] + 15) >> 4; k > 0; k --) {
		br_i15_muladd_small(x, 0, m);
	}
}

/* see inner.h */
void
br_i15_modpow(uint16_t *x,
	const unsigned char *e, size_t elen,
	const uint16_t *m, uint16_t m0i, uint16_t *t1, uint16_t *t2)
{
	size_t mlen;
	unsigned k;

	mlen = ((m[0] + 31) >> 4) * sizeof m[0];
	memcpy(t1, x, mlen);
	br_i15_to_monty(t1, m);
	br_i15_zero(x, m[0]);
	x[1] = 1;
	for (k = 0; k < ((unsigned)elen << 3); k ++) {
		uint32_t ctl;

		ctl = (e[elen - 1 - (k >> 3)] >> (k & 7)) & 1;
		br_i15_montymul(t2, x, t1, m, m0i);
		CCOPY(ctl, x, t2, mlen);
		br_i15_montymul(t2, t1, t1, m, m0i);
		memcpy(t1, t2, mlen);
	}
}

/* see inner.h */
void
br_i15_encode(void *dst, size_t len, const uint16_t *x)
{
	unsigned char *buf;
	size_t u, xlen;
	uint32_t acc;
	int acc_len;

	xlen = (x[0] + 15) >> 4;
	if (xlen == 0) {
		memset(dst, 0, len);
		return;
	}
	u = 1;
	acc = 0;
	acc_len = 0;
	buf = dst;
	while (len -- > 0) {
		if (acc_len < 8) {
			if (u <= xlen) {
				acc += (uint32_t)x[u ++] << acc_len;
			}
			acc_len += 15;
		}
		buf[len] = (unsigned char)acc;
		acc >>= 8;
		acc_len -= 8;
	}
}

/* see inner.h */
uint32_t
br_i15_decode_mod(uint16_t *x, const void *src, size_t len, const uint16_t *m)
{
	/*
	 * Two-pass algorithm: in the first pass, we determine whether the
	 * value fits; in the second pass, we do the actual write.
	 *
	 * During the first pass, 'r' contains the comparison result so
	 * far:
	 *  0x00000000   value is equal to the modulus
	 *  0x00000001   value is greater than the modulus
	 *  0xFFFFFFFF   value is lower than the modulus
	 *
	 * Since we iterate starting with the least significant bytes (at
	 * the end of src[]), each new comparison overrides the previous
	 * except when the comparison yields 0 (equal).
	 *
	 * During the second pass, 'r' is either 0xFFFFFFFF (value fits)
	 * or 0x00000000 (value does not fit).
	 *
	 * We must iterate over all bytes of the source, _and_ possibly
	 * some extra virutal bytes (with value 0) so as to cover the
	 * complete modulus as well. We also add 4 such extra bytes beyond
	 * the modulus length because it then guarantees that no accumulated
	 * partial word remains to be processed.
	 */
	const unsigned char *buf;
	size_t mlen, tlen;
	int pass;
	uint32_t r;

	buf = src;
	mlen = (m[0] + 15) >> 4;
	tlen = (mlen << 1);
	if (tlen < len) {
		tlen = len;
	}
	tlen += 4;
	r = 0;
	for (pass = 0; pass < 2; pass ++) {
		size_t u, v;
		uint32_t acc;
		int acc_len;

		v = 1;
		acc = 0;
		acc_len = 0;
		for (u = 0; u < tlen; u ++) {
			uint32_t b;

			if (u < len) {
				b = buf[len - 1 - u];
			} else {
				b = 0;
			}
			acc |= (b << acc_len);
			acc_len += 8;
			if (acc_len >= 15) {
				uint32_t xw;

				xw = acc & (uint32_t)0x7FFF;
				acc_len -= 15;
				acc = b >> (8 - acc_len);
				if (v <= mlen) {
					if (pass) {
						x[v] = r & xw;
					} else {
						uint32_t cc;

						cc = (uint32_t)CMP(xw, m[v]);
						r = MUX(EQ(cc, 0), r, cc);
					}
				} else {
					if (!pass) {
						r = MUX(EQ(xw, 0), r, 1);
					}
				}
				v ++;
			}
		}

		/*
		 * When we reach this point at the end of the first pass:
		 * r is either 0, 1 or -1; we want to set r to 0 if it
		 * is equal to 0 or 1, and leave it to -1 otherwise.
		 *
		 * When we reach this point at the end of the second pass:
		 * r is either 0 or -1; we want to leave that value
		 * untouched. This is a subcase of the previous.
		 */
		r >>= 1;
		r |= (r << 1);
	}

	x[0] = m[0];
	return r & (uint32_t)1;
}
