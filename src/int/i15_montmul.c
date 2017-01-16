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
		f = MUL15((d[1] + MUL15(x[u + 1], y[1])) & 0x7FFF, m0i)
			& 0x7FFF;

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
		dh = zh >> 15;
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
