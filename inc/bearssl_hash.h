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

#ifndef BR_BEARSSL_HASH_H__
#define BR_BEARSSL_HASH_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Hash Functions
 * --------------
 *
 * For hash function 'xxx', the following elements are defined:
 *
 * br_xxx_vtable
 *    An externally defined instance of br_hash_class.
 *
 * br_xxx_SIZE
 *    A macro that evaluates to the output size (in bytes) of the
 *    hash function.
 *
 * br_xxx_ID
 *    A macro that evaluates to a symbolic identifier for the hash
 *    function. Such identifiers are used with HMAC and signature
 *    algorithm implementations.
 *    NOTE: the numerical value of these identifiers MUST match the
 *    constants for hash function identification in TLS 1.2 (see RFC
 *    5246, section 7.4.1.4.1). These are values 1 to 6, for MD5,
 *    SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512, respectively.
 *
 * br_xxx_context
 *    Context for an ongoing computation. It is allocated by the
 *    caller, and a pointer to it is passed to all functions. A
 *    context contains no interior pointer, so it can be moved around
 *    and cloned (with a simple memcpy() or equivalent) in order to
 *    capture the function state at some point. Computations that use
 *    distinct context structures are independent of each other. The
 *    first field of br_xxx_context is always a pointer to the
 *    br_xxx_vtable structure; br_xxx_init() sets that pointer.
 *
 * br_xxx_init(br_xxx_context *ctx)
 *    Initialize the provided context. Previous contents of the structure
 *    are ignored. This calls resets the context to the start of a new
 *    hash computation.
 *
 * br_xxx_update(br_xxx_context *ctx, const void *data, size_t len)
 *    Add some more bytes to the hash computation represented by the
 *    provided context.
 *
 * br_xxx_out(const br_xxx_context *ctx, void *out)
 *    Complete the hash computation and write the result in the provided
 *    buffer. The output buffer MUST be large enough to accomodate the
 *    result. The context is NOT modified by this operation, so this
 *    function can be used to get a "partial hash" while still keeping
 *    the possibility of adding more bytes to the input.
 *
 * br_xxx_state(const br_xxx_context *ctx, void *out)
 *    Get a copy of the "current state" for the computation so far. For
 *    MD functions (MD5, SHA-1, SHA-2 family), this is the running state
 *    resulting from the processing of the last complete input block.
 *    Returned value is the current input length (in bytes).
 *
 * br_xxx_set_state(br_xxx_context *ctx, const void *stb, uint64_t count)
 *    Set the internal state to the provided values. The 'stb' and 'count'
 *    values shall match that which was obtained from br_xxx_state(). This
 *    restores the hash state only if the state values were at an
 *    appropriate block boundary. This does NOT set the 'vtable' pointer
 *    in the context.
 *
 * Context structures can be discarded without any explicit deallocation.
 * Hash function implementations are purely software and don't reserve
 * any resources outside of the context structure itself.
 *
 * Implemented hash functions are:
 *
 *   Function    Name      Output length   State length
 *
 *   MD5         md5       16              16
 *   SHA-1       sha1      20              20
 *   SHA-224     sha224    28              32
 *   SHA-256     sha256    32              32
 *   SHA-384     sha384    48              64
 *   SHA-512     sha512    64              64
 *   MD5+SHA-1   md5sha1   36              36
 *
 * (MD5+SHA-1 is the concatenation of MD5 and SHA-1 computed over the
 * same input; in the implementation, the internal data buffer is
 * shared, thus making it more memory-efficient than separate MD5 and
 * SHA-1. It can be useful in implementing SSL 3.0, TLS 1.0 and TLS
 * 1.1.)
 *
 *
 * An object-oriented API is also available: the first field of the
 * context is a pointer to a br_hash_class structure, that has the
 * following contents:
 *
 *   context_size   total size of the required context structure
 *   desc           descriptor (see below)
 *   init           context initialization or reset (function pointer)
 *   update         process some more bytes (function pointer)
 *   out            get hash output so far (function pointer)
 *   state          get copy of internal state (function pointer)
 *   set_state      reset the internal state (function pointer)
 *
 * The descriptor is a combination of the following elements:
 *   bits 0 to 7     hash algorithm identifier
 *   bits 8 to 14    hash output size (in bytes)
 *   bits 15 to 22   hash internal state size (in bytes)
 *   bits 23 to 26   log (base 2) of hash internal block size (in bytes)
 *   bit 28          1 if using MD padding, 0 otherwise
 *   bit 29          1 if MD padding uses a 128-bit bit length, 0 otherwise
 *   bit 30          1 if MD padding is big-endian, 0 otherwise
 *
 * For function 'xxx', the br_xxx_init() function sets the first field
 * to a pointer to the relevant br_hash_class instance (i.e.
 * br_xxx_vtable).
 *
 * Users of this object-oriented API may make the following assumptions:
 *   Hash output size is no more than 64 bytes.
 *   Hash internal state size is no more than 64 bytes.
 *   Internal block size is a power of two, no less than 2^4 and no more
 *   than 2^8.
 * For functions that do not have an internal block size that is a
 * power of 2, the relevant element is 0.
 */

typedef struct br_hash_class_ br_hash_class;
struct br_hash_class_ {
	size_t context_size;
	uint32_t desc;
	void (*init)(const br_hash_class **ctx);
	void (*update)(const br_hash_class **ctx, const void *data, size_t len);
	void (*out)(const br_hash_class *const *ctx, void *dst);
	uint64_t (*state)(const br_hash_class *const *ctx, void *dst);
	void (*set_state)(const br_hash_class **ctx,
		const void *stb, uint64_t count);
};

#define BR_HASHDESC_ID(id)           ((uint32_t)(id) << BR_HASHDESC_ID_OFF)
#define BR_HASHDESC_ID_OFF           0
#define BR_HASHDESC_ID_MASK          0xFF

#define BR_HASHDESC_OUT(size)        ((uint32_t)(size) << BR_HASHDESC_OUT_OFF)
#define BR_HASHDESC_OUT_OFF          8
#define BR_HASHDESC_OUT_MASK         0x7F

#define BR_HASHDESC_STATE(size)      ((uint32_t)(size) << BR_HASHDESC_STATE_OFF)
#define BR_HASHDESC_STATE_OFF        15
#define BR_HASHDESC_STATE_MASK       0xFF

#define BR_HASHDESC_LBLEN(ls)        ((uint32_t)(ls) << BR_HASHDESC_LBLEN_OFF)
#define BR_HASHDESC_LBLEN_OFF        23
#define BR_HASHDESC_LBLEN_MASK       0x0F

#define BR_HASHDESC_MD_PADDING       ((uint32_t)1 << 28)
#define BR_HASHDESC_MD_PADDING_128   ((uint32_t)1 << 29)
#define BR_HASHDESC_MD_PADDING_BE    ((uint32_t)1 << 30)

/*
 * Specific hash functions.
 *
 * Rules for contexts:
 * -- No interior pointer.
 * -- No pointer to external dynamically allocated resources.
 * -- First field is called 'vtable' and is a pointer to a
 *    const-qualified br_hash_class instance (pointer is set by init()).
 * -- SHA-224 and SHA-256 contexts are identical.
 * -- SHA-384 and SHA-512 contexts are identical.
 *
 * Thus, contexts can be moved and cloned to capture the hash function
 * current state; and there is no need for any explicit "release" function.
 */

#define br_md5_ID     1
#define br_md5_SIZE   16
extern const br_hash_class br_md5_vtable;
typedef struct {
	const br_hash_class *vtable;
	unsigned char buf[64];
	uint64_t count;
	uint32_t val[4];
} br_md5_context;
void br_md5_init(br_md5_context *ctx);
void br_md5_update(br_md5_context *ctx, const void *data, size_t len);
void br_md5_out(const br_md5_context *ctx, void *out);
uint64_t br_md5_state(const br_md5_context *ctx, void *out);
void br_md5_set_state(br_md5_context *ctx, const void *stb, uint64_t count);

#define br_sha1_ID     2
#define br_sha1_SIZE   20
extern const br_hash_class br_sha1_vtable;
typedef struct {
	const br_hash_class *vtable;
	unsigned char buf[64];
	uint64_t count;
	uint32_t val[5];
} br_sha1_context;
void br_sha1_init(br_sha1_context *ctx);
void br_sha1_update(br_sha1_context *ctx, const void *data, size_t len);
void br_sha1_out(const br_sha1_context *ctx, void *out);
uint64_t br_sha1_state(const br_sha1_context *ctx, void *out);
void br_sha1_set_state(br_sha1_context *ctx, const void *stb, uint64_t count);

#define br_sha224_ID     3
#define br_sha224_SIZE   28
extern const br_hash_class br_sha224_vtable;
typedef struct {
	const br_hash_class *vtable;
	unsigned char buf[64];
	uint64_t count;
	uint32_t val[8];
} br_sha224_context;
void br_sha224_init(br_sha224_context *ctx);
void br_sha224_update(br_sha224_context *ctx, const void *data, size_t len);
void br_sha224_out(const br_sha224_context *ctx, void *out);
uint64_t br_sha224_state(const br_sha224_context *ctx, void *out);
void br_sha224_set_state(br_sha224_context *ctx,
	const void *stb, uint64_t count);

#define br_sha256_ID     4
#define br_sha256_SIZE   32
extern const br_hash_class br_sha256_vtable;
typedef br_sha224_context br_sha256_context;
void br_sha256_init(br_sha256_context *ctx);
#define br_sha256_update      br_sha224_update
void br_sha256_out(const br_sha256_context *ctx, void *out);
#define br_sha256_state       br_sha224_state
#define br_sha256_set_state   br_sha224_set_state

#define br_sha384_ID     5
#define br_sha384_SIZE   48
extern const br_hash_class br_sha384_vtable;
typedef struct {
	const br_hash_class *vtable;
	unsigned char buf[128];
	uint64_t count;
	uint64_t val[8];
} br_sha384_context;
void br_sha384_init(br_sha384_context *ctx);
void br_sha384_update(br_sha384_context *ctx, const void *data, size_t len);
void br_sha384_out(const br_sha384_context *ctx, void *out);
uint64_t br_sha384_state(const br_sha384_context *ctx, void *out);
void br_sha384_set_state(br_sha384_context *ctx,
	const void *stb, uint64_t count);

#define br_sha512_ID     6
#define br_sha512_SIZE   64
extern const br_hash_class br_sha512_vtable;
typedef br_sha384_context br_sha512_context;
void br_sha512_init(br_sha512_context *ctx);
#define br_sha512_update      br_sha384_update
void br_sha512_out(const br_sha512_context *ctx, void *out);
#define br_sha512_state       br_sha384_state
#define br_sha512_set_state   br_sha384_set_state

/*
 * "md5sha1" is a special hash function that computes both MD5 and SHA-1
 * on the same input, and produces a 36-byte output (MD5 and SHA-1
 * concatenation, in that order). State size is also 36 bytes.
 */
#define br_md5sha1_ID     0
#define br_md5sha1_SIZE   36
extern const br_hash_class br_md5sha1_vtable;
typedef struct {
	const br_hash_class *vtable;
	unsigned char buf[64];
	uint64_t count;
	uint32_t val_md5[4];
	uint32_t val_sha1[5];
} br_md5sha1_context;
void br_md5sha1_init(br_md5sha1_context *ctx);
void br_md5sha1_update(br_md5sha1_context *ctx, const void *data, size_t len);
void br_md5sha1_out(const br_md5sha1_context *ctx, void *out);
uint64_t br_md5sha1_state(const br_md5sha1_context *ctx, void *out);
void br_md5sha1_set_state(br_md5sha1_context *ctx,
	const void *stb, uint64_t count);

/*
 * The br_hash_compat_context type is a type which is large enough to
 * serve as context for all standard hash functions defined above.
 */
typedef union {
	const br_hash_class *vtable;
	br_md5_context md5;
	br_sha1_context sha1;
	br_sha224_context sha224;
	br_sha256_context sha256;
	br_sha384_context sha384;
	br_sha512_context sha512;
} br_hash_compat_context;

/*
 * The multi-hasher is a construct that handles hashing of the same input
 * data with several hash functions, with a single shared input buffer.
 * It can handle MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512
 * simultaneously, though which functions are activated depends on
 * the set implementation pointers.
 */

typedef struct {
	unsigned char buf[128];
	uint64_t count;
	uint32_t val_32[25];
	uint64_t val_64[16];
	const br_hash_class *impl[6];
} br_multihash_context;

/*
 * Clear a complete multihash context. This should always be called once
 * on a given context, before setting implementation pointers.
 */
void br_multihash_zero(br_multihash_context *ctx);

/*
 * Set a hash function implementation, identified by ID.
 */
static inline void
br_multihash_setimpl(br_multihash_context *ctx,
	int id, const br_hash_class *impl)
{
	/*
	 * This code relies on hash functions ID being values 1 to 6,
	 * in the MD5 to SHA-512 order.
	 */
	ctx->impl[id - 1] = impl;
}

/*
 * Get the configured hash implementation, identified by ID. This returns
 * NULL for unsupported hash implementations. The hash identifier MUST
 * be a valid one (from br_md5_ID to br_sha512_ID, inclusive).
 */
static inline const br_hash_class *
br_multihash_getimpl(const br_multihash_context *ctx, int id)
{
	return ctx->impl[id - 1];
}

/*
 * Reset a multihash context. The hash functions for which implementation
 * pointers have been set are reset and initialized.
 */
void br_multihash_init(br_multihash_context *ctx);

/*
 * Input some bytes into the context.
 */
void br_multihash_update(br_multihash_context *ctx,
	const void *data, size_t len);

/*
 * Get the hash of the bytes injected so far, with the specified hash
 * function. The hash function is given by ID (e.g. br_md5_ID for MD5).
 * The hash output is written on 'dst'. The hash length is returned (in
 * bytes); if the specified hash function is not implemented by this
 * context, then this function returns 0.
 *
 * Obtaining the hash output does not invalidate the current hashing
 * operation, thus "partial hashes" can be obtained.
 */
size_t br_multihash_out(const br_multihash_context *ctx, int id, void *dst);

/*
 * Type for a GHASH implementation. GHASH is a sort of keyed hash meant
 * to be used to implement GCM in combination with a block cipher (with
 * 16-byte blocks).
 *
 * The y[] array has length 16 bytes and is used for input and output; in
 * a complete GHASH run, it starts with an all-zero value. h[] is a 16-byte
 * value that serves as key (it is derived from the encryption key in GCM,
 * using the block cipher). The data length (len) is expressed in bytes.
 *
 * If the data length is not a multiple of 16, then the data is implicitly
 * padded with zeros up to the next multiple of 16. Thus, when using GHASH
 * in GCM, this method may be called twice, for the associated data and
 * for the ciphertext, respectively; the zero-padding implements exactly
 * the GCM rules.
 */
typedef void (*br_ghash)(void *y, const void *h, const void *data, size_t len);

/*
 * Implementation of GHASH using normal 32x32->64 multiplications. It is
 * constant-time (if multiplications are constant-time).
 */
void br_ghash_ctmul(void *y, const void *h, const void *data, size_t len);

/*
 * Implementation of GHASH using normal 32x32->32 multiplications; this
 * may be faster than br_ghash_ctmul() on platforms for which the inner
 * multiplication opcode does not yield the upper 32 bits of the product.
 * It is constant-time (if multiplications are constant-time).
 */
void br_ghash_ctmul32(void *y, const void *h, const void *data, size_t len);

/*
 * Implementation of GHASH using 64x64->64 multiplications. It is
 * constant-time (if multiplications are constant-time).
 */
void br_ghash_ctmul64(void *y, const void *h, const void *data, size_t len);

#endif
