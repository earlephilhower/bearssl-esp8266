/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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

static const uint32_t P256_P[] = {
	0x00000108,
	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x00000007,
	0x00000000, 0x00000000, 0x00000040, 0x7FFFFF80,
	0x000000FF
};

static const uint32_t P256_B[] = {
	0x00000108,
	0x6FEE1803, 0x6229C4BD, 0x21B139BE, 0x327150AA,
	0x3567802E, 0x3F7212ED, 0x012E4355, 0x782DD38D,
	0x0000000E
};

/* see inner.h */
const br_ec_prime_i31_curve br_ec_prime_i31_secp256r1 = {
	P256_P,
	P256_B,
	0x00000001
};
