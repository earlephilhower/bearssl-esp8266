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

/* see bearssl_ssl.h */
void
br_ssl_server_init_full_rsa(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_rsa_private_key *sk)
{
	/*
	 * The "full" profile supports all implemented cipher suites.
	 *
	 * Rationale for suite order, from most important to least
	 * important rule:
	 *
	 * -- Don't use 3DES if AES is available.
	 * -- Try to have Forward Secrecy (ECDHE suite) if possible.
	 * -- ChaCha20+Poly1305 is better than AES/GCM (faster, smaller).
	 * -- GCM is better than CBC.
	 * -- AES-128 is preferred over AES-256 (AES-128 is already
	 *    strong enough, and AES-256 is 40% more expensive).
	 */
	static const uint16_t suites[] = {
		BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
	};

	/*
	 * All hash functions are activated.
	 * Note: the X.509 validation engine will nonetheless refuse to
	 * validate signatures that use MD5 as hash function.
	 */
	static const br_hash_class *hashes[] = {
		&br_md5_vtable,
		&br_sha1_vtable,
		&br_sha224_vtable,
		&br_sha256_vtable,
		&br_sha384_vtable,
		&br_sha512_vtable
	};

	int id;

	/*
	 * Reset server context and set supported versions from TLS-1.0
	 * to TLS-1.2 (inclusive).
	 */
	br_ssl_server_zero(cc);
	br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);

	/*
	 * Set suites and elliptic curve implementation (for ECDHE).
	 */
	br_ssl_engine_set_suites(&cc->eng, suites,
		(sizeof suites) / (sizeof suites[0]));
	br_ssl_engine_set_ec(&cc->eng, &br_ec_prime_i31);

	/*
	 * Set the "server policy": handler for the certificate chain
	 * and private key operations.
	 */
	br_ssl_server_set_single_rsa(cc, chain, chain_len, sk,
		BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
		br_rsa_i31_private, br_rsa_i31_pkcs1_sign);

	/*
	 * Set supported hash functions.
	 */
	for (id = br_md5_ID; id <= br_sha512_ID; id ++) {
		const br_hash_class *hc;

		hc = hashes[id - 1];
		br_ssl_engine_set_hash(&cc->eng, id, hc);
	}

	/*
	 * Set the PRF implementations.
	 */
	br_ssl_engine_set_prf10(&cc->eng, &br_tls10_prf);
	br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
	br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);

	/*
	 * Symmetric encryption. We use the "constant-time"
	 * implementations, which are the safest.
	 *
	 * On architectures detected as "64-bit", use the 64-bit
	 * versions (aes_ct64, ghash_ctmul64).
	 */
#if BR_64
	br_ssl_engine_set_aes_cbc(&cc->eng,
		&br_aes_ct64_cbcenc_vtable,
		&br_aes_ct64_cbcdec_vtable);
	br_ssl_engine_set_aes_ctr(&cc->eng,
		&br_aes_ct64_ctr_vtable);
	br_ssl_engine_set_ghash(&cc->eng,
		&br_ghash_ctmul64);
#else
	br_ssl_engine_set_aes_cbc(&cc->eng,
		&br_aes_ct_cbcenc_vtable,
		&br_aes_ct_cbcdec_vtable);
	br_ssl_engine_set_aes_ctr(&cc->eng,
		&br_aes_ct_ctr_vtable);
	br_ssl_engine_set_ghash(&cc->eng,
		&br_ghash_ctmul);
#endif
	br_ssl_engine_set_des_cbc(&cc->eng,
		&br_des_ct_cbcenc_vtable,
		&br_des_ct_cbcdec_vtable);
	br_ssl_engine_set_chacha20(&cc->eng,
		&br_chacha20_ct_run);
	br_ssl_engine_set_poly1305(&cc->eng,
		&br_poly1305_ctmul_run);

	/*
	 * Set the SSL record engines (CBC, GCM, ChaCha20).
	 */
	br_ssl_engine_set_cbc(&cc->eng,
		&br_sslrec_in_cbc_vtable,
		&br_sslrec_out_cbc_vtable);
	br_ssl_engine_set_gcm(&cc->eng,
		&br_sslrec_in_gcm_vtable,
		&br_sslrec_out_gcm_vtable);
	br_ssl_engine_set_chapol(&cc->eng,
		&br_sslrec_in_chapol_vtable,
		&br_sslrec_out_chapol_vtable);
}
