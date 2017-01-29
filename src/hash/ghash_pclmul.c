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
 * This is the GHASH implementation that leverages the pclmulqdq opcode
 * (from the AES-NI instructions).
 */

#if BR_AES_X86NI

#if BR_AES_X86NI_GCC
/* #pragma GCC target "sse2,ssse3,pclmul" */
#include <tmmintrin.h>
#include <wmmintrin.h>
#include <cpuid.h>
#endif

#if BR_AES_X86NI_MSC
#include <intrin.h>
#endif

/* see bearssl_hash.h */
BR_TARGET("ssse3,pclmul")
void
br_ghash_pclmul(void *y, const void *h, const void *data, size_t len)
{
	/*
	 * TODO: loop below processes one 16-bit word at a time. We
	 * could parallelize, using:
	 *   ((y+x0)*h+x1)*h = (y+x0)*(h^2) + x1*h
	 * i.e. precompute h^2, then handle two words at a time, mostly
	 * in parallel (this may extend to more words as well...).
	 */

	const unsigned char *buf;
	__m128i yx, hx;
	__m128i h0, h1, h2;
	__m128i byteswap_index;

	byteswap_index = _mm_set_epi8(
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	yx = _mm_loadu_si128(y);
	hx = _mm_loadu_si128(h);
	yx = _mm_shuffle_epi8(yx, byteswap_index);
	hx = _mm_shuffle_epi8(hx, byteswap_index);

	/*
	 * We byte-swap y and h for full big-endian interpretation
	 * (see below).
	 */

	h0 = hx;
	h1 = _mm_shuffle_epi32(hx, 0x0E);
	h2 = _mm_xor_si128(h0, h1);

	buf = data;
	while (len > 0) {
		__m128i x;
		__m128i t0, t1, t2, v0, v1, v2, v3;
		__m128i y0, y1, y2;

		/*
		 * Load next 128-bit word. If there are not enough bytes
		 * for the next word, we pad it with zeros (as per the
		 * API for this function; it's also what is useful for
		 * implementation of GCM).
		 */
		if (len >= 16) {
			x = _mm_loadu_si128((const void *)buf);
			buf += 16;
			len -= 16;
		} else {
			unsigned char tmp[16];

			memcpy(tmp, buf, len);
			memset(tmp + len, 0, (sizeof tmp) - len);
			x = _mm_loadu_si128((void *)tmp);
			len = 0;
		}

		/*
		 * Specification of GCM is basically "full little-endian",
		 * i.e. leftmost bit is most significant; but decoding
		 * performed by _mm_loadu_si128 is "mixed endian" (leftmost
		 * _byte_ is least significant, but within each byte, the
		 * leftmost _bit_ is most significant). We could reverse
		 * bits in each byte; however, it is more efficient to
		 * swap the bytes and thus emulate full big-endian
		 * decoding.
		 *
		 * Big-endian works here because multiplication in
		 * GF[2](X) is "carry-less", thereby allowing reversal:
		 * if rev_n(x) consists in reversing the order of bits
		 * in x, then:
		 *   rev_128(A)*rev_128(B) = rev_255(A*B)
		 * so we can compute A*B by using rev_128(A) and rev_128(B),
		 * and an extra shift at the end (because 255 != 256). Bit
		 * reversal is exactly what happens when converting from
		 * full little-endian to full big-endian.
		 */
		x = _mm_shuffle_epi8(x, byteswap_index);
		yx = _mm_xor_si128(yx, x);

		/*
		 * We want the product to be broken down into four
		 * 64-bit values, because there is no SSE* opcode that
		 * can do a shift on a 128-bit value.
		 */
		y0 = yx;
		y1 = _mm_shuffle_epi32(yx, 0x0E);
		y2 = _mm_xor_si128(y0, y1);
		t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
		t1 = _mm_clmulepi64_si128(yx, hx, 0x11);
		t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
		t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
		v0 = t0;
		v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
		v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
		v3 = _mm_shuffle_epi32(t1, 0x0E);

		/*
		 * Do the corrective 1-bit shift (255->256).
		 */
		v3 = _mm_or_si128(
			_mm_slli_epi64(v3, 1),
			_mm_srli_epi64(v2, 63));
		v2 = _mm_or_si128(
			_mm_slli_epi64(v2, 1),
			_mm_srli_epi64(v1, 63));
		v1 = _mm_or_si128(
			_mm_slli_epi64(v1, 1),
			_mm_srli_epi64(v0, 63));
		v0 = _mm_slli_epi64(v0, 1);

		/*
		 * Perform polynomial reduction into GF(2^128).
		 */
		v2 = _mm_xor_si128(
			v2,
			_mm_xor_si128(
				_mm_xor_si128(
					v0,
					_mm_srli_epi64(v0, 1)),
				_mm_xor_si128(
					_mm_srli_epi64(v0, 2),
					_mm_srli_epi64(v0, 7))));
		v1 = _mm_xor_si128(
			_mm_xor_si128(
				v1,
				_mm_slli_epi64(v0, 63)),
			_mm_xor_si128(
				_mm_slli_epi64(v0, 62),
				_mm_slli_epi64(v0, 57)));
		v3 = _mm_xor_si128(
			v3,
			_mm_xor_si128(
				_mm_xor_si128(
					v1,
					_mm_srli_epi64(v1, 1)),
				_mm_xor_si128(
					_mm_srli_epi64(v1, 2),
					_mm_srli_epi64(v1, 7))));
		v2 = _mm_xor_si128(
			_mm_xor_si128(
				v2,
				_mm_slli_epi64(v1, 63)),
			_mm_xor_si128(
				_mm_slli_epi64(v1, 62),
				_mm_slli_epi64(v1, 57)));

		/*
		 * We reduced toward the high words (v2 and v3), which
		 * are the new value for y.
		 */
		yx = _mm_unpacklo_epi64(v2, v3);
	}

	yx = _mm_shuffle_epi8(yx, byteswap_index);
	_mm_storeu_si128(y, yx);
}

/*
 * Test CPU support for PCLMULQDQ.
 */
static int
pclmul_supported(void)
{
	/*
	 * Bit mask for features in ECX:
	 *    1   PCLMULQDQ support
	 */
#define MASK   0x00000002

#if BR_AES_X86NI_GCC
	unsigned eax, ebx, ecx, edx;

	if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
		return (ecx & MASK) == MASK;
	} else {
		return 0;
	}
#elif BR_AES_X86NI_MSC
	int info[4];

	__cpuid(info, 1);
	return ((uint32_t)info[2] & MASK) == MASK;
#else
	return 0;
#endif

#undef MASK
}

/* see bearssl_hash.h */
br_ghash
br_ghash_pclmul_get(void)
{
	return pclmul_supported() ? &br_ghash_pclmul : 0;
}

#else

/* see bearssl_hash.h */
br_ghash
br_ghash_pclmul_get(void)
{
	return 0;
}

#endif
