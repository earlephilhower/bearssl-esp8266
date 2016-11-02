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

#ifndef BR_BEARSSL_RAND_H__
#define BR_BEARSSL_RAND_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Pseudo-Random Generators
 * ------------------------
 *
 * A PRNG is a state-based engine that outputs pseudo-random bytes on
 * demand. It is initialized with an initial seed, and additional seed
 * bytes can be added afterwards. Bytes produced depend on the seeds
 * and also on the exact sequence of calls (including sizes requested
 * for each call).
 *
 * An object-oriented API is defined, with rules similar to that of
 * hash functions. The context structure for a PRNG must start with
 * a pointer to the vtable. The vtable contains the following fields:
 *
 *  context_size   size of the context structure for this PRNG
 *  init           initialize context with an initial seed
 *  generate       produce some pseudo-random bytes
 *  update         insert some additional seed
 *
 * Note that the init() method may accept additional parameters, provided
 * as a 'const void *' pointer at API level. These additional parameters
 * depend on the implemented PRNG.
 */

typedef struct br_prng_class_ br_prng_class;
struct br_prng_class_ {
	size_t context_size;
	void (*init)(const br_prng_class **ctx, const void *params,
		const void *seed, size_t seed_len);
	void (*generate)(const br_prng_class **ctx, void *out, size_t len);
	void (*update)(const br_prng_class **ctx,
		const void *seed, size_t seed_len);
};

/*
 * HMAC_DRBG is a pseudo-random number generator based on HMAC (with
 * an underlying hash function). HMAC_DRBG is specified in NIST Special
 * Publication 800-90A. It works as a stateful machine:
 * -- It has an internal state.
 * -- The state can be updated with additional "entropy" (some bytes
 *    provided from the outside).
 * -- Each request is for some bits (up to some limit). For each request,
 *    an internal "reseed counter" is incremented.
 * -- When the reseed counter reaches a given threshold, a reseed is
 *    necessary.
 *
 * Standard limits are quite high: each request can produce up to 2^19
 * bits (i.e. 64 kB of data), and the threshold for the reseed counter
 * is 2^48. In practice, we cannot really reach that reseed counter, so
 * the implementation simply omits the counter. Similarly, we consider
 * that it is up to callers NOT to ask for more than 64 kB of randomness
 * in one go. Under these conditions, this implementation cannot fail,
 * and thus functions need not return any status code.
 *
 * (Asking for more than 64 kB of data in one generate() call won't make
 * the implementation fail, and, as far as we know, it will not induce
 * any actual weakness; this is "merely" out of the formal usage range
 * defined for HMAC_DRBG.)
 *
 * A dedicated context structure (caller allocated, as usual) contains
 * the current PRNG state.
 *
 * For the OOP interface, the "additional parameters" are a pointer to
 * the class of the hash function to use.
 */

typedef struct {
	const br_prng_class *vtable;
	unsigned char K[64];
	unsigned char V[64];
	const br_hash_class *digest_class;
} br_hmac_drbg_context;

extern const br_prng_class br_hmac_drbg_vtable;

/*
 * Initialize a HMAC_DRBG instance, with the provided initial seed (of
 * 'len' bytes). The 'seed' used here is what is called, in SP 800-90A
 * terminology, the concatenation of the "seed", "nonce" and
 * "personalization string", in that order.
 *
 * Formally, the underlying digest can only be SHA-1 or one of the SHA-2
 * functions. This implementation also works with any other implemented
 * hash function (e.g. MD5), but such usage is non-standard and not
 * recommended.
 */
void br_hmac_drbg_init(br_hmac_drbg_context *ctx,
	const br_hash_class *digest_class, const void *seed, size_t len);

/*
 * Obtain some pseudorandom bits from HMAC_DRBG. The provided context
 * is updated. The output bits are written in 'out' ('len' bytes). The
 * size of the requested chunk of pseudorandom bits MUST NOT exceed
 * 64 kB (the function won't fail if more bytes are requested, but
 * the usage will be outside of the HMAC_DRBG specification limits).
 */
void br_hmac_drbg_generate(br_hmac_drbg_context *ctx, void *out, size_t len);

/*
 * Update an HMAC_DRBG instance with some new entropy. The extra 'seed'
 * complements the current state but does not completely replace any
 * previous seed. The process is such that pushing new entropy, even of
 * questionable quality, will not make the output "less random" in any
 * practical way.
 */
void br_hmac_drbg_update(br_hmac_drbg_context *ctx,
	const void *seed, size_t len);

/*
 * Get the hash function implementation used by a given instance of
 * HMAC_DRBG.
 */
static inline const br_hash_class *
br_hmac_drbg_get_hash(const br_hmac_drbg_context *ctx)
{
	return ctx->digest_class;
}

#endif
