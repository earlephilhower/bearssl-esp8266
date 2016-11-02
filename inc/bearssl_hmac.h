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

#ifndef BR_BEARSSL_HMAC_H__
#define BR_BEARSSL_HMAC_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_hash.h"

/*
 * HMAC
 * ----
 *
 * HMAC is initialized with a key and an underlying hash function; it
 * then fills a "key context". That context contains the processed
 * key.
 *
 * With the key context, a HMAC context can be initialized to process
 * the input bytes and obtain the MAC output. The key context is not
 * modified during that process, and can be reused.
 *
 * IMPORTANT: HMAC shall be used only with functions that have the
 * following properties:
 *   hash output size does not exceed 64 bytes
 *   hash internal state size does not exceed 64 bytes
 *   internal block length is a power of 2 between 16 and 256 bytes
 */

/*
 * Key context.
 */
typedef struct {
	const br_hash_class *dig_vtable;
	unsigned char ksi[64], kso[64];
} br_hmac_key_context;

/*
 * Initialize the key context with the provided key, using the hash function
 * identified by digest_class.
 */
void br_hmac_key_init(br_hmac_key_context *kc,
	const br_hash_class *digest_class, const void *key, size_t key_len);

/*
 * A helper structure that is big enough to accommodate all context
 * structures for all hash functions for which HMAC is supported.
 */
typedef union {
	const br_hash_class *vtable;
	br_md5_context md5;
	br_sha1_context sha1;
	br_sha224_context sha224;
	br_sha256_context sha256;
	br_sha384_context sha384;
	br_sha512_context sha512;
} br_hmac_allhash_context;

/*
 * Context for an HMAC computation.
 */
typedef struct {
	br_hmac_allhash_context dig;
	unsigned char kso[64];
	size_t out_len;
} br_hmac_context;

/*
 * Initialize a HMAC context with a key context. The key context is
 * unmodified. Relevant data from the key context is immediately copied;
 * the key context can thus be independently reused, modified or released
 * without impacting this HMAC computation.
 *
 * An explicit output length can be specified; the actual output length
 * will be the minimum of that value and the natural HMAC output length.
 * If out_len is 0, then the natural HMAC output length is selected.
 */
void br_hmac_init(br_hmac_context *ctx,
	const br_hmac_key_context *kc, size_t out_len);

/*
 * Get the MAC output size. The context must have been initialized.
 */
#define br_hmac_size(ctx)   ((ctx)->out_len)

/*
 * Process some more bytes.
 */
void br_hmac_update(br_hmac_context *ctx, const void *data, size_t len);

/*
 * Compute the HMAC output. The destination buffer MUST be large enough
 * to accomodate the result. The context is NOT modified; further bytes
 * may be processed. Thus, "partial HMAC" values can be efficiently
 * obtained.
 *
 * Returned value is the output length (in bytes).
 */
size_t br_hmac_out(const br_hmac_context *ctx, void *out);

/*
 * Compute the HMAC output in constant time. Some extra input bytes are
 * processed, then the output is computed. The extra input consists in
 * the 'len' bytes pointed to by 'data'. The 'len' parameter must lie
 * between 'min_len' and 'max_len' (inclusive); max_len bytes are
 * actually read from 'data'. Computing time (and memory access pattern)
 * will not depend upon the data bytes or the value of 'len'.
 *
 * The output is written in the 'out' buffer, that MUST be large enough
 * to receive it.
 *
 * The difference max_len-min_len MUST be less than 2^30.
 *
 * This function computes the output properly only if the underlying
 * hash function uses MD padding (i.e. MD5, SHA-1, SHA-224, SHA-256,
 * SHA-384 or SHA-512).
 *
 * The provided context is NOT modified.
 *
 * Returned value is the MAC length (in bytes).
 */
size_t br_hmac_outCT(const br_hmac_context *ctx,
	const void *data, size_t len, size_t min_len, size_t max_len,
	void *out);

#endif
