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

#ifndef BR_BEARSSL_RSA_H__
#define BR_BEARSSL_RSA_H__

#include <stddef.h>
#include <stdint.h>

/*
 * RSA
 * ---
 *
 * A RSA engine consists in two functions, for public-key and private-key
 * operations (modular exponentiations). In both cases, the same buffer is
 * used as source and destination.
 *
 * Key elements are provided as arrays of bytes, in big-endian unsigned
 * encoding (leading zeros are correctly skipped, hence signed encodings
 * can also be used). The source/destination array (x[]) is an array of
 * bytes that, per PKCS#1 rules, MUST have the same length as the modulus,
 * exactly: missing or extra leading bytes, even of value 0x00, are not
 * tolerated for x[].
 *
 * Parameter validation: the engine MUST gracefully handle incorrect key
 * parameters (e.g. an even modulus); it needs not detect all cases of
 * incorrect key parameters. For public key operations, the engine MUST
 * validate the length of x[] (it must match the numerical length, in
 * bytes, of the modulus); it MUST also check that the provided x[]
 * decodes to an integer that is numerically less than the modulus. For
 * private key operation, the engine may assume that the length and
 * contents of x[] are appropriate (it MUST NOT allow an invalid value
 * to result in a buffer overflow, but an invalid input x[] may result
 * in an undetected invalid output).
 *
 * Constant-time requirements: the following information may leak through
 * execution time and memory access pattern:
 * -- the actual bit length of the modulus;
 * -- the actual bit length of each prime factor;
 * -- the byte lengths as provided to the function calls.
 */

/*
 * A structure type for a RSA public key, consisting in a modulus and
 * a public exponent, encoded in unsigned big-endian format. The two
 * arrays may be larger than needed; functions that accept a RSA public
 * key are supposed to check the actual modulus length when needed.
 */
typedef struct {
	unsigned char *n;
	size_t nlen;
	unsigned char *e;
	size_t elen;
} br_rsa_public_key;

/*
 * A structure type for a RSA private key. The key elements are:
 *   n_bitlen   modulus bit length
 *   p          prime modulus factor
 *   q          other prime modulus factor (may be greater or lower than p)
 *   dp         private exponent, reduced modulo p-1
 *   dq         private exponent, reduced modulo q-1
 *   iq         CRT coefficient: q*iq = 1 mod p.
 */
typedef struct {
	uint32_t n_bitlen;
	unsigned char *p;
	size_t plen;
	unsigned char *q;
	size_t qlen;
	unsigned char *dp;
	size_t dplen;
	unsigned char *dq;
	size_t dqlen;
	unsigned char *iq;
	size_t iqlen;
} br_rsa_private_key;

/*
 * Type for a public-key engine. The source buffer x[], of size xlen,
 * is modified in place.
 *
 * Returned value is 1 on success, 0 on error.
 *
 * If the source buffer length (xlen) does not exactly match the modulus
 * length, then an error is reported and x[] is unmodified.
 */
typedef uint32_t (*br_rsa_public)(unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);

/*
 * Type for a RSA signature verification engine (PKCS#1 v1.5 signatures).
 * Parameters are:
 * -- The signature itself. The provided array is NOT modified.
 * -- The encoded OID for the hash function. The provided array must begin
 *    with a single byte that contains the length of the OID value (in
 *    bytes), followed by exactly that many bytes.
 *    This parameter may be NULL, in which case the raw hash value should
 *    be used with the PKCS#1 v1.5 "type 1" padding (used in SSL/TLS up
 *    to TLS-1.1, with a 36-byte hash value).
 * -- The hash output length, in bytes.
 * -- The public key.
 * -- An output buffer for the hash value. The caller must still compare
 *    it with the hash of the data over which the signature is computed.
 *
 * CONSTRAINTS:
 * -- Hash length MUST be no more than 64 bytes.
 * -- OID value length MUST be no more than 32 bytes (i.e. hash_oid[0]
 *    must have a value in the 0..32 range, inclusive).
 *
 * This function verifies that the signature length (xlen) matches the
 * modulus length (this function returns 0 on mismatch). If the modulus
 * size exceeds the maximum supported RSA size, then the function also
 * returns 0.
 *
 * Returned value is 1 on success, 0 on error.
 *
 * Implementations of this type need not be constant-time.
 */
typedef uint32_t (*br_rsa_pkcs1_vrfy)(const unsigned char *x, size_t xlen,
	const unsigned char *hash_oid, size_t hash_len,
	const br_rsa_public_key *pk, unsigned char *hash_out);

/*
 * Type for a private-key engine. The x[] buffer is modified in place, and
 * its length is inferred from the modulus length (x[] is assumed to have
 * a length of (sk->n_bitlen+7)/8 bytes).
 *
 * Returned value is 1 on success, 0 on error.
 */
typedef uint32_t (*br_rsa_private)(unsigned char *x,
	const br_rsa_private_key *sk);

/*
 * Type for a RSA signature generation engine (PKCS#1 v1.5 signatures).
 * Parameters are:
 * -- The encoded OID for the hash function. The provided array must begin
 *    with a single byte that contains the length of the OID value (in
 *    bytes), followed by exactly that many bytes.
 *    This parameter may be NULL, in which case the raw hash value should
 *    be used with the PKCS#1 v1.5 "type 1" padding (used in SSL/TLS up
 *    to TLS-1.1, with a 36-byte hash value).
 * -- The hashed data, and length (in bytes).
 * -- The private key.
 * -- The output buffer.
 *
 * Returned value is 1 on success, 0 on error. Error conditions include
 * a too small modulus for the provided hash OID and value, or some
 * invalid key parameters. The signature length is exactly
 * (sk->n_bitlen+7)/8 bytes.
 *
 * This function is expected to be constant-time with regards to the
 * private key bytes (lengths of the modulus and the individual factors
 * may leak, though) and to the hashed data.
 */
typedef uint32_t (*br_rsa_pkcs1_sign)(const unsigned char *hash_oid,
	const unsigned char *hash, size_t hash_len,
	const br_rsa_private_key *sk, unsigned char *x);

/*
 * RSA "i32" engine. Integers are internally represented as arrays of
 * 32-bit integers, and the core multiplication primitive is the
 * 32x32->64 multiplication.
 */

uint32_t br_rsa_i32_public(unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);
uint32_t br_rsa_i32_pkcs1_vrfy(const unsigned char *x, size_t xlen,
	const unsigned char *hash_oid, size_t hash_len,
	const br_rsa_public_key *pk, unsigned char *hash_out);
uint32_t br_rsa_i32_private(unsigned char *x,
	const br_rsa_private_key *sk);
uint32_t br_rsa_i32_pkcs1_sign(const unsigned char *hash_oid,
	const unsigned char *hash, size_t hash_len,
	const br_rsa_private_key *sk, unsigned char *x);

/*
 * RSA "i31" engine. Similar to i32, but only 31 bits are used per 32-bit
 * word. This uses slightly more stack space (about 4% more) and code
 * space, but it quite faster.
 */

uint32_t br_rsa_i31_public(unsigned char *x, size_t xlen,
	const br_rsa_public_key *pk);
uint32_t br_rsa_i31_pkcs1_vrfy(const unsigned char *x, size_t xlen,
	const unsigned char *hash_oid, size_t hash_len,
	const br_rsa_public_key *pk, unsigned char *hash_out);
uint32_t br_rsa_i31_private(unsigned char *x,
	const br_rsa_private_key *sk);
uint32_t br_rsa_i31_pkcs1_sign(const unsigned char *hash_oid,
	const unsigned char *hash, size_t hash_len,
	const br_rsa_private_key *sk, unsigned char *x);

/*
 * Perform RSA decryption for SSL/TLS. This function uses the provided core
 * and private key to decrypt the message in data[] of size 'len'. The
 * buffer is modified; the decryption result MUST have length 48, and
 * is written into the first 48 bytes of data[].
 *
 * In success, this rturns 1. On error, 0 is returned, and the buffer
 * contents are indeterminate.
 */
uint32_t br_rsa_ssl_decrypt(br_rsa_private core, const br_rsa_private_key *sk,
	unsigned char *data, size_t len);

#endif
