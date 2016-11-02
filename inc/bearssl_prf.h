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

#ifndef BR_BEARSSL_PRF_H__
#define BR_BEARSSL_PRF_H__

#include <stddef.h>
#include <stdint.h>

/*
 * The TLS PRF
 * -----------
 *
 * TLS 1.0 and 1.1 define a PRF that is based on both MD5 and SHA-1. This
 * is implemented by the br_tls10_prf() function.
 *
 * TLS 1.2 redefines the PRF, using an explicit hash function. The
 * br_tls12_sha256_prf() and br_tls12_sha384_prf() functions apply that
 * PRF with, respectively, SHA-256 and SHA-384.
 *
 * The PRF always uses as input three parameters: a "secret" (some
 * bytes), a "label" (ASCII string), and a "seed" (again some bytes).
 * An arbitrary output length can be produced.
 */

void br_tls10_prf(void *dst, size_t len,
	const void *secret, size_t secret_len,
	const char *label, const void *seed, size_t seed_len);

void br_tls12_sha256_prf(void *dst, size_t len,
	const void *secret, size_t secret_len,
	const char *label, const void *seed, size_t seed_len);

void br_tls12_sha384_prf(void *dst, size_t len,
	const void *secret, size_t secret_len,
	const char *label, const void *seed, size_t seed_len);

/*
 * A convenient type name for a PRF implementation.
 */
typedef void (*br_tls_prf_impl)(void *dst, size_t len,
	const void *secret, size_t secret_len,
	const char *label, const void *seed, size_t seed_len);

#endif
