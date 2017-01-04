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
 * This file contains some additional functions for "i15" big integers.
 * These functions are needed to support RSA.
 */

/* see inner.h */
void
br_i15_decode_reduce(uint16_t *x,
	const void *src, size_t len, const uint16_t *m)
{
	uint32_t m_ebitlen, m_rbitlen;
	size_t mblen, k;
	const unsigned char *buf;
	uint32_t acc;
	int acc_len;

	/*
	 * Get the encoded bit length.
	 */
	m_ebitlen = m[0];

	/*
	 * Special case for an invalid (null) modulus.
	 */
	if (m_ebitlen == 0) {
		x[0] = 0;
		return;
	}

	/*
	 * Clear the destination.
	 */
	br_i15_zero(x, m_ebitlen);

	/*
	 * First decode directly as many bytes as possible. This requires
	 * computing the actual bit length.
	 */
	m_rbitlen = m_ebitlen >> 4;
	m_rbitlen = (m_ebitlen & 15) + (m_rbitlen << 4) - m_rbitlen;
	mblen = (m_rbitlen + 7) >> 3;
	k = mblen - 1;
	if (k >= len) {
		br_i15_decode(x, src, len);
		x[0] = m_ebitlen;
		return;
	}
	buf = src;
	br_i15_decode(x, buf, k);
	x[0] = m_ebitlen;

	/*
	 * Input remaining bytes, using 15-bit words.
	 */
	acc = 0;
	acc_len = 0;
	while (k < len) {
		uint32_t v;

		v = buf[k ++];
		acc = (acc << 8) | v;
		acc_len += 8;
		if (acc_len >= 15) {
			br_i15_muladd_small(x, acc >> (acc_len - 15), m);
			acc_len -= 15;
			acc &= ~((uint32_t)-1 << acc_len);
		}
	}

	/*
	 * We may have some bits accumulated. We then perform a shift to
	 * be able to inject these bits as a full 15-bit word.
	 */
	if (acc_len != 0) {
		acc = (acc | (x[1] << acc_len)) & 0x7FFF;
		br_i15_rshift(x, 15 - acc_len);
		br_i15_muladd_small(x, acc, m);
	}
}

/* see inner.h */
void
br_i15_reduce(uint16_t *x, const uint16_t *a, const uint16_t *m)
{
	uint32_t m_bitlen, a_bitlen;
	size_t mlen, alen, u;

	m_bitlen = m[0];
	mlen = (m_bitlen + 15) >> 4;

	x[0] = m_bitlen;
	if (m_bitlen == 0) {
		return;
	}

	/*
	 * If the source is shorter, then simply copy all words from a[]
	 * and zero out the upper words.
	 */
	a_bitlen = a[0];
	alen = (a_bitlen + 15) >> 4;
	if (a_bitlen < m_bitlen) {
		memcpy(x + 1, a + 1, alen * sizeof *a);
		for (u = alen; u < mlen; u ++) {
			x[u + 1] = 0;
		}
		return;
	}

	/*
	 * The source length is at least equal to that of the modulus.
	 * We must thus copy N-1 words, and input the remaining words
	 * one by one.
	 */
	memcpy(x + 1, a + 2 + (alen - mlen), (mlen - 1) * sizeof *a);
	x[mlen] = 0;
	for (u = 1 + alen - mlen; u > 0; u --) {
		br_i15_muladd_small(x, a[u], m);
	}
}

/* see inner.h */
void
br_i15_mulacc(uint16_t *d, const uint16_t *a, const uint16_t *b)
{
	size_t alen, blen, u;

	alen = (a[0] + 15) >> 4;
	blen = (b[0] + 15) >> 4;
	d[0] = a[0] + b[0];
	for (u = 0; u < blen; u ++) {
		uint32_t f;
		size_t v;
		uint32_t cc;

		f = b[1 + u];
		cc = 0;
		for (v = 0; v < alen; v ++) {
			uint32_t z;

			z = (uint32_t)d[1 + u + v] + MUL15(f, a[1 + v]) + cc;
			cc = z >> 15;
			d[1 + u + v] = z & 0x7FFF;
		}
		d[1 + u + alen] = cc;
	}
}
