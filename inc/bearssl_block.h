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

#ifndef BR_BEARSSL_BLOCK_H__
#define BR_BEARSSL_BLOCK_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Block Ciphers
 * -------------
 *
 * For a block cipher implementation, up to three separate sets of
 * functions are provided, for CBC encryption, CBC decryption, and CTR
 * encryption/decryption. Each set has its own context structure,
 * initialized with the encryption key. Each set of functions is
 * provided both as named functions, and through an OOP interface.
 *
 * For CBC encryption and decryption, the data to encrypt or decrypt is
 * referenced as a sequence of blocks. The implementations assume that
 * there is no partial block; no padding is applied or removed. The
 * caller is responsible for handling any kind of padding.
 *
 * Function for CTR encryption are defined only for block ciphers with
 * blocks of 16 bytes or more (i.e. AES, but not DES/3DES).
 *
 * Each implemented block cipher is identified by an "internal name"
 * from which are derived the names of structures and functions that
 * implement the cipher. For the block cipher of internal name "xxx",
 * the following are defined:
 *
 * br_xxx_BLOCK_SIZE
 *    A macro that evaluates to the block size (in bytes) of the
 *    cipher. For all implemented block ciphers, this value is a
 *    power of two.
 *
 * br_xxx_cbcenc_keys
 *    Context structure that contains the subkeys resulting from the key
 *    expansion. These subkeys are appropriate for CBC encryption. The
 *    structure first field is called 'vtable' and points to the
 *    appropriate OOP structure.
 *
 * br_xxx_cbcenc_init(br_xxx_cbcenc_keys *ctx, const void *key, size_t len)
 *    Perform key expansion: subkeys for CBC encryption are computed and
 *    written in the provided context structure. The key length MUST be
 *    adequate for the implemented block cipher. This function also sets
 *    the 'vtable' field.
 *
 * br_xxx_cbcenc_run(const br_xxx_cbcenc_keys *ctx,
 *                   void *iv, void *data, size_t len)
 *    Perform CBC encryption of 'len' bytes, in place. The encrypted data
 *    replaces the cleartext. 'len' MUST be a multiple of the block length
 *    (if it is not, the function may loop forever or overflow a buffer).
 *    The IV is provided with the 'iv' pointer; it is also updated with
 *    a copy of the last encrypted block.
 *
 * br_xxx_cbcdec_keys
 *    Context structure that contains the subkeys resulting from the key
 *    expansion. These subkeys are appropriate for CBC decryption. The
 *    structure first field is called 'vtable' and points to the
 *    appropriate OOP structure.
 *
 * br_xxx_cbcdec_init(br_xxx_cbcenc_keys *ctx, const void *key, size_t len)
 *    Perform key expansion: subkeys for CBC decryption are computed and
 *    written in the provided context structure. The key length MUST be
 *    adequate for the implemented block cipher. This function also sets
 *    the 'vtable' field.
 *
 * br_xxx_cbcdec_run(const br_xxx_cbcdec_keys *ctx,
 *                   void *iv, void *data, size_t num_blocks)
 *    Perform CBC decryption of 'len' bytes, in place. The decrypted data
 *    replaces the ciphertext. 'len' MUST be a multiple of the block length
 *    (if it is not, the function may loop forever or overflow a buffer).
 *    The IV is provided with the 'iv' pointer; it is also updated with
 *    a copy of the last encrypted block.
 *
 * br_xxx_ctr_keys
 *    Context structure that contains the subkeys resulting from the key
 *    expansion. These subkeys are appropriate for CTR encryption and
 *    decryption. The structure first field is called 'vtable' and
 *    points to the appropriate OOP structure.
 *
 * br_xxx_ctr_init(br_xxx_ctr_keys *ctx, const void *key, size_t len)
 *    Perform key expansion: subkeys for CTR encryption and decryption
 *    are computed and written in the provided context structure. The
 *    key length MUST be adequate for the implemented block cipher. This
 *    function also sets the 'vtable' field.
 *
 * br_xxx_ctr_run(const br_xxx_ctr_keys *ctx, const void *iv,
 *                uint32_t cc, void *data, size_t len) [returns uint32_t]
 *    Perform CTR encryption/decryption of some data. Processing is done
 *    "in place" (the output data replaces the input data). This function
 *    implements the "standard incrementing function" from NIST SP800-38A,
 *    annex B: the IV length shall be 4 bytes less than the block size
 *    (i.e. 12 bytes for AES) and the counter is the 32-bit value starting
 *    with 'cc'. The data length ('len') is not necessarily a multiple of
 *    the block size. The new counter value is returned, which supports
 *    chunked processing, provided that each chunk length (except possibly
 *    the last one) is a multiple of the block size.
 *
 *
 * It shall be noted that the key expansion functions return 'void'. If
 * the provided key length is not allowed, then there will be no error
 * reporting; implementations need not validate the key length, thus an
 * invalid key length may result in undefined behaviour (e.g. buffer
 * overflow).
 *
 * Subkey structures contain no interior pointer, and no external
 * resources are allocated upon key expansion. They can thus be
 * discarded without any explicit deallocation.
 *
 *
 * Object-oriented API: each context structure begins with a field
 * (called 'vtable') that points to an instance of a structure that
 * references the relevant functions through pointers. Each such
 * structure contains the following:
 *
 *   context_size     size (in bytes) of the context structure for subkeys
 *   block_size       cipher block size (in bytes)
 *   log_block_size   base-2 logarithm of cipher block size
 *   init             pointer to the key expansion function
 *   run              pointer to the encryption/decryption function
 *
 * Static, constant instances of these structures are defined, under
 * the names:
 *
 *   br_xxx_cbcenc_vtable
 *   br_xxx_cbcdec_vtable
 *   br_xxx_ctr_vtable
 *
 *
 * Implemented Block Ciphers
 * -------------------------
 * 
 *   Function   Name         Allowed key lengths (bytes)
 *
 *   AES        aes_ct       16, 24 and 32
 *   AES        aes_ct64     16, 24 and 32
 *   AES        aes_big      16, 24 and 32
 *   AES        aes_small    16, 24 and 32
 *   DES        des_ct       8, 16 and 24
 *   DES        des_tab      8, 16 and 24
 *
 * 'aes_big' is a "classical" AES implementation, using tables. It
 * is fast but not constant-time, since it makes data-dependent array
 * accesses.
 *
 * 'aes_small' is an AES implementation optimized for code size. It
 * is substantially slower than 'aes_big'; it is not constant-time
 * either.
 *
 * 'aes_ct' is a constant-time implementation of AES; its code is about
 * as big as that of 'aes_big', while its performance is comparable to
 * that of 'aes_small'. However, it is constant-time. This
 * implementation should thus be considered to be the "default" AES in
 * BearSSL, to be used unless the operational context guarantees that a
 * non-constant-time implementation is safe, or an architecture-specific
 * constant-time implementation can be used (e.g. using dedicated
 * hardware opcodes).
 *
 * 'aes_ct64' is another constant-time implementation of AES. It is
 * similar to 'aes_ct' but uses 64-bit values, for faster processing
 * on 64-bit machines.
 *
 * 'des_tab' is a classic, table-based implementation of DES/3DES. It
 * is not constant-time.
 *
 * 'des_ct' is an constant-time implementation of DES/3DES. It is
 * substantially slower than 'des_tab'.
 */

typedef struct br_block_cbcenc_class_ br_block_cbcenc_class;
struct br_block_cbcenc_class_ {
	size_t context_size;
	unsigned block_size;
	unsigned log_block_size;
	void (*init)(const br_block_cbcenc_class **ctx,
		const void *key, size_t key_len);
	void (*run)(const br_block_cbcenc_class *const *ctx,
		void *iv, void *data, size_t len);
};

typedef struct br_block_cbcdec_class_ br_block_cbcdec_class;
struct br_block_cbcdec_class_ {
	size_t context_size;
	unsigned block_size;
	unsigned log_block_size;
	void (*init)(const br_block_cbcdec_class **ctx,
		const void *key, size_t key_len);
	void (*run)(const br_block_cbcdec_class *const *ctx,
		void *iv, void *data, size_t len);
};

typedef struct br_block_ctr_class_ br_block_ctr_class;
struct br_block_ctr_class_ {
	size_t context_size;
	unsigned block_size;
	unsigned log_block_size;
	void (*init)(const br_block_ctr_class **ctx,
		const void *key, size_t key_len);
	uint32_t (*run)(const br_block_ctr_class *const *ctx,
		const void *iv, uint32_t cc, void *data, size_t len);
};

/*
 * Traditional, table-based AES implementation. It is fast, but uses
 * internal tables (in particular a 1 kB table for encryption, another
 * 1 kB table for decryption, and a 256-byte table for key schedule),
 * and it is not constant-time. In contexts where cache-timing attacks
 * apply, this implementation may leak the secret key.
 */
#define br_aes_big_BLOCK_SIZE   16
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_big_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_big_cbcdec_keys;
typedef struct {
	const br_block_ctr_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_big_ctr_keys;
extern const br_block_cbcenc_class br_aes_big_cbcenc_vtable;
extern const br_block_cbcdec_class br_aes_big_cbcdec_vtable;
extern const br_block_ctr_class br_aes_big_ctr_vtable;
void br_aes_big_cbcenc_init(br_aes_big_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_aes_big_cbcdec_init(br_aes_big_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_aes_big_ctr_init(br_aes_big_ctr_keys *ctx,
	const void *key, size_t len);
void br_aes_big_cbcenc_run(const br_aes_big_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_aes_big_cbcdec_run(const br_aes_big_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);
uint32_t br_aes_big_ctr_run(const br_aes_big_ctr_keys *ctx,
	const void *iv, uint32_t cc, void *data, size_t len);

/*
 * AES implementation optimized for size. It is slower than the
 * traditional table-based AES implementation, but requires much less
 * code. It still uses data-dependent table accesses (albeit within a
 * much smaller 256-byte table), which makes it conceptually vulnerable
 * to cache-timing attacks.
 */
#define br_aes_small_BLOCK_SIZE   16
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_small_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_small_cbcdec_keys;
typedef struct {
	const br_block_ctr_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_small_ctr_keys;
extern const br_block_cbcenc_class br_aes_small_cbcenc_vtable;
extern const br_block_cbcdec_class br_aes_small_cbcdec_vtable;
extern const br_block_ctr_class br_aes_small_ctr_vtable;
void br_aes_small_cbcenc_init(br_aes_small_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_aes_small_cbcdec_init(br_aes_small_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_aes_small_ctr_init(br_aes_small_ctr_keys *ctx,
	const void *key, size_t len);
void br_aes_small_cbcenc_run(const br_aes_small_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_aes_small_cbcdec_run(const br_aes_small_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);
uint32_t br_aes_small_ctr_run(const br_aes_small_ctr_keys *ctx,
	const void *iv, uint32_t cc, void *data, size_t len);

/*
 * Constant-time AES implementation. Its size is similar to that of
 * 'aes_big', and its performance is similar to that of 'aes_small' (faster
 * decryption, slower encryption). However, it is constant-time, i.e.
 * immune to cache-timing and similar attacks.
 */
#define br_aes_ct_BLOCK_SIZE   16
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_ct_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_ct_cbcdec_keys;
typedef struct {
	const br_block_ctr_class *vtable;
	uint32_t skey[60];
	unsigned num_rounds;
} br_aes_ct_ctr_keys;
extern const br_block_cbcenc_class br_aes_ct_cbcenc_vtable;
extern const br_block_cbcdec_class br_aes_ct_cbcdec_vtable;
extern const br_block_ctr_class br_aes_ct_ctr_vtable;
void br_aes_ct_cbcenc_init(br_aes_ct_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_aes_ct_cbcdec_init(br_aes_ct_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_aes_ct_ctr_init(br_aes_ct_ctr_keys *ctx,
	const void *key, size_t len);
void br_aes_ct_cbcenc_run(const br_aes_ct_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_aes_ct_cbcdec_run(const br_aes_ct_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);
uint32_t br_aes_ct_ctr_run(const br_aes_ct_ctr_keys *ctx,
	const void *iv, uint32_t cc, void *data, size_t len);

/*
 * 64-bit constant-time AES implementation. It is similar to 'aes_ct'
 * but uses 64-bit registers, making it about twice faster than 'aes_ct'
 * on 64-bit platforms, while remaining constant-time and with a similar
 * code size. (The doubling in performance is only for CBC decryption
 * and CTR mode; CBC encryption is non-parallel and cannot benefit from
 * the larger registers.)
 */
#define br_aes_ct64_BLOCK_SIZE   16
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint64_t skey[30];
	unsigned num_rounds;
} br_aes_ct64_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint64_t skey[30];
	unsigned num_rounds;
} br_aes_ct64_cbcdec_keys;
typedef struct {
	const br_block_ctr_class *vtable;
	uint64_t skey[30];
	unsigned num_rounds;
} br_aes_ct64_ctr_keys;
extern const br_block_cbcenc_class br_aes_ct64_cbcenc_vtable;
extern const br_block_cbcdec_class br_aes_ct64_cbcdec_vtable;
extern const br_block_ctr_class br_aes_ct64_ctr_vtable;
void br_aes_ct64_cbcenc_init(br_aes_ct64_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_aes_ct64_cbcdec_init(br_aes_ct64_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_aes_ct64_ctr_init(br_aes_ct64_ctr_keys *ctx,
	const void *key, size_t len);
void br_aes_ct64_cbcenc_run(const br_aes_ct64_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_aes_ct64_cbcdec_run(const br_aes_ct64_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);
uint32_t br_aes_ct64_ctr_run(const br_aes_ct64_ctr_keys *ctx,
	const void *iv, uint32_t cc, void *data, size_t len);

/*
 * These structures are large enough to accommodate subkeys for all
 * AES implementations.
 */
typedef union {
	const br_block_cbcenc_class *vtable;
	br_aes_big_cbcenc_keys big;
	br_aes_small_cbcenc_keys small;
	br_aes_ct_cbcenc_keys ct;
	br_aes_ct64_cbcenc_keys ct64;
} br_aes_gen_cbcenc_keys;
typedef union {
	const br_block_cbcdec_class *vtable;
	br_aes_big_cbcdec_keys big;
	br_aes_small_cbcdec_keys small;
	br_aes_ct_cbcdec_keys ct;
	br_aes_ct64_cbcdec_keys ct64;
} br_aes_gen_cbcdec_keys;
typedef union {
	const br_block_ctr_class *vtable;
	br_aes_big_ctr_keys big;
	br_aes_small_ctr_keys small;
	br_aes_ct_ctr_keys ct;
	br_aes_ct64_ctr_keys ct64;
} br_aes_gen_ctr_keys;

/*
 * Traditional, table-based implementation for DES/3DES. Since tables are
 * used, cache-timing attacks are conceptually possible.
 */
#define br_des_tab_BLOCK_SIZE   8
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint32_t skey[96];
	unsigned num_rounds;
} br_des_tab_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint32_t skey[96];
	unsigned num_rounds;
} br_des_tab_cbcdec_keys;
extern const br_block_cbcenc_class br_des_tab_cbcenc_vtable;
extern const br_block_cbcdec_class br_des_tab_cbcdec_vtable;
void br_des_tab_cbcenc_init(br_des_tab_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_des_tab_cbcdec_init(br_des_tab_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_des_tab_cbcenc_run(const br_des_tab_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_des_tab_cbcdec_run(const br_des_tab_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);

/*
 * Constant-time implementation for DES/3DES. It is substantially slower
 * (by a factor of about 4x), but also immune to cache-timing attacks.
 */
#define br_des_ct_BLOCK_SIZE   8
typedef struct {
	const br_block_cbcenc_class *vtable;
	uint32_t skey[96];
	unsigned num_rounds;
} br_des_ct_cbcenc_keys;
typedef struct {
	const br_block_cbcdec_class *vtable;
	uint32_t skey[96];
	unsigned num_rounds;
} br_des_ct_cbcdec_keys;
extern const br_block_cbcenc_class br_des_ct_cbcenc_vtable;
extern const br_block_cbcdec_class br_des_ct_cbcdec_vtable;
void br_des_ct_cbcenc_init(br_des_ct_cbcenc_keys *ctx,
	const void *key, size_t len);
void br_des_ct_cbcdec_init(br_des_ct_cbcdec_keys *ctx,
	const void *key, size_t len);
void br_des_ct_cbcenc_run(const br_des_ct_cbcenc_keys *ctx, void *iv,
	void *data, size_t len);
void br_des_ct_cbcdec_run(const br_des_ct_cbcdec_keys *ctx, void *iv,
	void *data, size_t len);

/*
 * These structures are large enough to accommodate subkeys for all
 * DES/3DES implementations.
 */
typedef union {
	const br_block_cbcenc_class *vtable;
	br_des_tab_cbcenc_keys tab;
	br_des_ct_cbcenc_keys ct;
} br_des_gen_cbcenc_keys;
typedef union {
	const br_block_cbcdec_class *vtable;
	br_des_tab_cbcdec_keys tab;
	br_des_ct_cbcdec_keys ct;
} br_des_gen_cbcdec_keys;

#endif
