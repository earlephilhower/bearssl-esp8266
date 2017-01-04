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
 * These functions are needed to support ECDSA.
 */

/* see inner.h */
void
br_i15_rshift(uint16_t *x, int count)
{
	size_t u, len;
	unsigned r;

	len = (x[0] + 15) >> 4;
	if (len == 0) {
		return;
	}
	r = x[1] >> count;
	for (u = 2; u <= len; u ++) {
		unsigned w;

		w = x[u];
		x[u - 1] = ((w << (15 - count)) | r) & 0x7FFF;
		r = w >> count;
	}
	x[len] = r;
}

/* see inner.h */
uint32_t
br_i15_bit_length(uint16_t *x, size_t xlen)
{
	uint32_t tw, twk;

	tw = 0;
	twk = 0;
	while (xlen -- > 0) {
		uint32_t w, c;

		c = EQ(tw, 0);
		w = x[xlen];
		tw = MUX(c, w, tw);
		twk = MUX(c, (uint32_t)xlen, twk);
	}
	return (twk << 4) + BIT_LENGTH(tw);
}

/* see inner.h */
void
br_i15_decode(uint16_t *x, const void *src, size_t len)
{
	const unsigned char *buf;
	size_t v;
	uint32_t acc;
	int acc_len;

	buf = src;
	v = 1;
	acc = 0;
	acc_len = 0;
	while (len -- > 0) {
		uint32_t b;

		b = buf[len];
		acc |= (b << acc_len);
		acc_len += 8;
		if (acc_len >= 15) {
			x[v ++] = acc & 0x7FFF;
			acc_len -= 15;
			acc >>= 15;
		}
	}
	if (acc_len != 0) {
		x[v ++] = acc;
	}
	x[0] = br_i15_bit_length(x + 1, v - 1);
}

/* see inner.h */
void
br_i15_from_monty(uint16_t *x, const uint16_t *m, uint16_t m0i)
{
	size_t len, u, v;

	len = (m[0] + 15) >> 4;
	for (u = 0; u < len; u ++) {
		uint32_t f, cc;

		f = MUL15(x[1], m0i) & 0x7FFF;
		cc = 0;
		for (v = 0; v < len; v ++) {
			uint32_t z;

			z = (uint32_t)x[v + 1] + MUL15(f, m[v + 1]) + cc;
			cc = z >> 15;
			if (v != 0) {
				x[v] = z & 0x7FFF;
			}
		}
		x[len] = cc;
	}

	/*
	 * We may have to do an extra subtraction, but only if the
	 * value in x[] is indeed greater than or equal to that of m[],
	 * which is why we must do two calls (first call computes the
	 * carry, second call performs the subtraction only if the carry
	 * is 0).
	 */
	br_i15_sub(x, m, NOT(br_i15_sub(x, m, 0)));
}
