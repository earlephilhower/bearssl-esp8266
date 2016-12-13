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
br_ssl_client_init_full(br_ssl_client_context *cc,
	br_x509_minimal_context *xc,
	const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num)
{
	/*
	 * The "full" profile supports all implemented cipher suites.
	 *
	 * Rationale for suite order, from most important to least
	 * important rule:
	 *
	 * -- Don't use 3DES if AES or ChaCha20 is available.
	 * -- Try to have Forward Secrecy (ECDHE suite) if possible.
	 * -- When not using Forward Secrecy, ECDH key exchange is
	 *    better than RSA key exchange (slightly more expensive on the
	 *    client, but much cheaper on the server, and it implies smaller
	 *    messages).
	 * -- ChaCha20+Poly1305 is better than AES/GCM (faster, smaller code).
	 * -- GCM is better than CBC.
	 * -- AES-128 is preferred over AES-256 (AES-128 is already
	 *    strong enough, and AES-256 is 40% more expensive).
	 */
	static const uint16_t suites[] = {
		BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
		BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
		BR_TLS_RSA_WITH_AES_128_CBC_SHA,
		BR_TLS_RSA_WITH_AES_256_CBC_SHA,
		BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
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
	 * Reset client context and set supported versions from TLS-1.0
	 * to TLS-1.2 (inclusive).
	 */
	br_ssl_client_zero(cc);
	br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);

	/*
	 * X.509 engine uses SHA-256 to hash certificate DN (for
	 * comparisons).
	 */
	br_x509_minimal_init(xc, &br_sha256_vtable,
		trust_anchors, trust_anchors_num);

	/*
	 * Set suites and asymmetric crypto implementations. We use the
	 * "i31" code for RSA (it is somewhat faster than the "i32"
	 * implementation).
	 * TODO: change that when better implementations are made available.
	 */
	br_ssl_engine_set_suites(&cc->eng, suites,
		(sizeof suites) / (sizeof suites[0]));
	br_ssl_client_set_rsapub(cc, &br_rsa_i31_public);
	br_ssl_engine_set_rsavrfy(&cc->eng, &br_rsa_i31_pkcs1_vrfy);
	br_ssl_engine_set_ec(&cc->eng, &br_ec_prime_i31);
	br_ssl_engine_set_ecdsa(&cc->eng, &br_ecdsa_i31_vrfy_asn1);
	br_x509_minimal_set_rsa(xc, &br_rsa_i31_pkcs1_vrfy);
	br_x509_minimal_set_ecdsa(xc,
		&br_ec_prime_i31, &br_ecdsa_i31_vrfy_asn1);

	/*
	 * Set supported hash functions, for the SSL engine and for the
	 * X.509 engine.
	 */
	for (id = br_md5_ID; id <= br_sha512_ID; id ++) {
		const br_hash_class *hc;

		hc = hashes[id - 1];
		br_ssl_engine_set_hash(&cc->eng, id, hc);
		br_x509_minimal_set_hash(xc, id, hc);
	}

	/*
	 * Link the X.509 engine in the SSL engine.
	 */
	br_ssl_engine_set_x509(&cc->eng, &xc->vtable);

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
	 * Set the SSL record engines (CBC, GCM).
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
