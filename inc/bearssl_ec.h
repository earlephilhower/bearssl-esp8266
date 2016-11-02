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

#ifndef BR_BEARSSL_EC_H__
#define BR_BEARSSL_EC_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Elliptic Curves
 * ---------------
 *
 * ECDSA signatures have two standard formats, called "raw" and "asn1".
 * Internally, such a signature is a pair of modular integers (r,s).
 * The "raw" format is the concatenation of the unsigned big-endian
 * encodings of these two integers, possibly left-padded with zeros so
 * that they have the same encoded length. The "asn1" format is the
 * DER encoding of an ASN.1 structure that contains the two integer
 * values:
 *
 *   ECDSASignature ::= SEQUENCE {
 *       r   INTEGER,
 *       s   INTEGER
 *   }
 *
 * Low-level implementations defined here work on the "raw" format.
 * Conversion functions are provided.
 *
 * Note that for a given signature, the "raw" format is not fully
 * deterministic, in that it does not enforce a minimal common length.
 * The functions below MUST ensure, when producing signatures, that
 * the signature length never exceeds 2*qlen, where qlen is the length,
 * in bytes, of the minimal unsigned big-endian encoding of the curve
 * subgroup order.
 *
 * Conversion of a "raw" format signature into "asn1" may enlarge a
 * signature by no more than 9 bytes for all supported curves.
 */

/*
 * Standard curve ID. These ID are equal to the assigned numerical
 * identifiers assigned to these curves for TLS:
 *    http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
#define BR_EC_sect163k1           1
#define BR_EC_sect163r1           2
#define BR_EC_sect163r2           3
#define BR_EC_sect193r1           4
#define BR_EC_sect193r2           5
#define BR_EC_sect233k1           6
#define BR_EC_sect233r1           7
#define BR_EC_sect239k1           8
#define BR_EC_sect283k1           9
#define BR_EC_sect283r1          10
#define BR_EC_sect409k1          11
#define BR_EC_sect409r1          12
#define BR_EC_sect571k1          13
#define BR_EC_sect571r1          14
#define BR_EC_secp160k1          15
#define BR_EC_secp160r1          16
#define BR_EC_secp160r2          17
#define BR_EC_secp192k1          18
#define BR_EC_secp192r1          19
#define BR_EC_secp224k1          20
#define BR_EC_secp224r1          21
#define BR_EC_secp256k1          22
#define BR_EC_secp256r1          23
#define BR_EC_secp384r1          24
#define BR_EC_secp521r1          25
#define BR_EC_brainpoolP256r1    26
#define BR_EC_brainpoolP384r1    27
#define BR_EC_brainpoolP512r1    28

/*
 * Structure for an EC public key.
 */
typedef struct {
	int curve;
	unsigned char *q;
	size_t qlen;
} br_ec_public_key;

/*
 * Structure for an EC private key.
 */
typedef struct {
	int curve;
	unsigned char *x;
	size_t xlen;
} br_ec_private_key;

/*
 * Type for an EC implementation.
 *
 *  supported_curves
 *     Bit mask for supported curves: if curve 'id' is supported, then
 *     bit '1 << id' is set.
 *
 *  generator
 *     Get a pointer to the conventional generator for a given curve.
 *
 *  order
 *     Get a pointer to the curve order (minimal unsigned big-endian
 *     encoding).
 *
 *  mul
 *     Compute x*G. Provided point G (encoded size Glen) must be valid and
 *     distinct from the point at infinity. 'x' must be non-zero and less
 *     than the curve order. On error, 0 is returned; an invalid G (or
 *     point at infinity) is always detected, as well as a case of x = 0.
 *     However, if x is a non-zero multiple of the curve order, then it is
 *     not guaranteed that an error is reported.
 *
 *  muladd
 *     compute x*A+y*B, result being written over A. Points and multipliers
 *     must fulfill the same conditions as for mul().
 */
typedef struct {
	uint32_t supported_curves;
	const unsigned char *(*generator)(int curve, size_t *len);
	const unsigned char *(*order)(int curve, size_t *len);
	uint32_t (*mul)(unsigned char *G, size_t Glen,
		const unsigned char *x, size_t xlen, int curve);
	uint32_t (*muladd)(unsigned char *A, const unsigned char *B, size_t len,
		const unsigned char *x, size_t xlen,
		const unsigned char *y, size_t ylen, int curve);
} br_ec_impl;

/*
 * The 'i31' implementation for elliptic curves. It supports secp256r1,
 * secp384r1 and secp521r1 (aka NIST curves P-256, P-384 and P-521).
 */
extern const br_ec_impl br_ec_prime_i31;

/*
 * Convert a signature from "raw" to "asn1". Conversion is done "in
 * place" and the new length is returned. Conversion may enlarge the
 * signature, but by no more than 9 bytes at most. On error, 0 is
 * returned (error conditions include an odd raw signature length, or an
 * oversized integer).
 */
size_t br_ecdsa_raw_to_asn1(void *sig, size_t sig_len);

/*
 * Convert a signature from "asn1" to "raw". Conversion is done "in
 * place" and the new length is returned. Conversion in that direction
 * always reduced signature length. On error, 0 is returned (error
 * conditions include an invalid signature format or an oversized
 * integer).
 */
size_t br_ecdsa_asn1_to_raw(void *sig, size_t sig_len);

/*
 * Type for an ECDSA signer function. A pointer to the EC implementation
 * is provided. The hash value is assumed to have the length inferred
 * from the designated hash function class.
 *
 * Signature is written in the buffer pointed to by 'sig', and the length
 * (in bytes) is returned. On error, nothing is written in the buffer,
 * and 0 is returned.
 *
 * The signature format is either "raw" or "asn1", depending on the
 * implementation; maximum length is predictable from the implemented
 * curve:
 *
 *   curve        raw   asn1
 *   NIST P-256    64     72
 *   NIST P-384    96    104
 *   NIST P-521   132    139
 */
typedef size_t (*br_ecdsa_sign)(const br_ec_impl *impl,
	const br_hash_class *hf, const void *hash_value,
	const br_ec_private_key *sk, void *sig);

/*
 * Verify ECDSA signature. Returned value is 1 on success, 0 on error.
 */
typedef uint32_t (*br_ecdsa_vrfy)(const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);

/*
 * ECDSA implementation using the "i31" integers.
 */
size_t br_ecdsa_i31_sign_asn1(const br_ec_impl *impl,
	const br_hash_class *hf, const void *hash_value,
	const br_ec_private_key *sk, void *sig);
size_t br_ecdsa_i31_sign_raw(const br_ec_impl *impl,
	const br_hash_class *hf, const void *hash_value,
	const br_ec_private_key *sk, void *sig);
uint32_t br_ecdsa_i31_vrfy_asn1(const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);
uint32_t br_ecdsa_i31_vrfy_raw(const br_ec_impl *impl,
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk, const void *sig, size_t sig_len);

#endif
