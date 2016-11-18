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

#ifndef BR_BEARSSL_SSL_H__
#define BR_BEARSSL_SSL_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_block.h"
#include "bearssl_hash.h"
#include "bearssl_hmac.h"
#include "bearssl_prf.h"
#include "bearssl_rand.h"
#include "bearssl_x509.h"

/*
 * SSL
 * ---
 *
 */

/* Optimal input buffer size. */
#define BR_SSL_BUFSIZE_INPUT    (16384 + 325)

/* Optimal output buffer size. */
#define BR_SSL_BUFSIZE_OUTPUT   (16384 + 85)

/* Optimal buffer size for monodirectional engine
   (shared input/output buffer). */
#define BR_SSL_BUFSIZE_MONO     BR_SSL_BUFSIZE_INPUT

/* Optimal buffer size for bidirectional engine
   (single buffer split into two separate input/output buffers). */
#define BR_SSL_BUFSIZE_BIDI     (BR_SSL_BUFSIZE_INPUT + BR_SSL_BUFSIZE_OUTPUT)

/*
 * Constants for known SSL/TLS protocol versions (SSL 3.0, TLS 1.0, TLS 1.1
 * and TLS 1.2). Note that though there is a constant for SSL 3.0, that
 * protocol version is not actually supported.
 */
#define BR_SSL30   0x0300
#define BR_TLS10   0x0301
#define BR_TLS11   0x0302
#define BR_TLS12   0x0303

/*
 * Error constants. They are used to report the reason why a context has
 * been marked as failed.
 *
 * Implementation note: SSL-level error codes should be in the 1..31
 * range. The 32..63 range is for certificate decoding and validation
 * errors. Received fatal alerts imply an error code in the 256..511 range.
 */

/* No error so far (0). */
#define BR_ERR_OK                      0

/* Caller-provided parameter is incorrect. */
#define BR_ERR_BAD_PARAM               1

/* Operation requested by the caller cannot be applied with the current
   context state (e.g. reading data while outgoing data is waiting to
   be sent). */
#define BR_ERR_BAD_STATE               2

/* Incoming protocol or record version is unsupported. */
#define BR_ERR_UNSUPPORTED_VERSION     3

/* Incoming record version does not match the expected version. */
#define BR_ERR_BAD_VERSION             4

/* Incoming record length is invalid. */
#define BR_ERR_BAD_LENGTH              5

/* Incoming record is too large to be processed, or buffer is too small
   for the handshake message to send. */
#define BR_ERR_TOO_LARGE               6

/* Decryption found an invalid padding, or the record MAC is not correct. */
#define BR_ERR_BAD_MAC                 7

/* No initial entropy was provided, and none can be obtained from the OS. */
#define BR_ERR_NO_RANDOM               8

/* Incoming record type is unknown. */
#define BR_ERR_UNKNOWN_TYPE            9

/* Incoming record or message has wrong type with regards to the
   current engine state. */
#define BR_ERR_UNEXPECTED             10

/* ChangeCipherSpec message from the peer has invalid contents. */
#define BR_ERR_BAD_CCS                12

/* Alert message from the peer has invalid contents (odd length). */
#define BR_ERR_BAD_ALERT              13

/* Incoming handshake message decoding failed. */
#define BR_ERR_BAD_HANDSHAKE          14

/* ServerHello contains a session ID which is larger than 32 bytes. */
#define BR_ERR_OVERSIZED_ID           15

/* Server wants to use a cipher suite that we did not claim to support.
   This is also reported if we tried to advertise a cipher suite that
   we do not support. */
#define BR_ERR_BAD_CIPHER_SUITE       16

/* Server wants to use a compression that we did not claim to support. */
#define BR_ERR_BAD_COMPRESSION        17

/* Server's max fragment length does not match client's. */
#define BR_ERR_BAD_FRAGLEN            18

/* Secure renegotiation failed. */
#define BR_ERR_BAD_SECRENEG           19

/* Server sent an extension type that we did not announce, or used the
   same extension type several times in a single ServerHello. */
#define BR_ERR_EXTRA_EXTENSION        20

/* Invalid Server Name Indication contents (when used by the server,
   this extension shall be empty). */
#define BR_ERR_BAD_SNI                21

/* Invalid ServerHelloDone from the server (length is not 0). */
#define BR_ERR_BAD_HELLO_DONE         22

/* Internal limit exceeded (e.g. server's public key is too large). */
#define BR_ERR_LIMIT_EXCEEDED         23

/* Finished message from peer does not match the expected value. */
#define BR_ERR_BAD_FINISHED           24

/* Session resumption attempt with distinct version or cipher suite. */
#define BR_ERR_RESUME_MISMATCH        25

/* Unsupported or invalid algorithm (ECDHE curve, signature algorithm,
   hash function). */
#define BR_ERR_INVALID_ALGORITHM      26

/* Invalid signature on ServerKeyExchange message. */
#define BR_ERR_BAD_SIGNATURE          27

/* I/O error or premature close on underlying transport stream. This
   error code is set only by the simplified I/O API ("br_sslio_*"). */
#define BR_ERR_IO                     31

/* When a fatal alert is received from the peer, the alert value is added
   to this constant. */
#define BR_ERR_RECV_FATAL_ALERT      256

/* When a fatal alert is sent to the peer, the alert value is added
   to this constant. */
#define BR_ERR_SEND_FATAL_ALERT      512

/* ===================================================================== */

/*
 * The decryption engine for incoming records is an object that implements
 * the following functions:
 *
 *   check_length   test whether the provided record length is valid
 *   decrypt        decrypt and verify the provided record
 *
 * The decrypt() function receives as parameters a pointer to its context
 * structure, the record type, the record version, a pointer to the
 * start of the record payload, and a pointer to a word containing the
 * payload length. The decrypt() function may assume that the length is
 * proper (check_length() was called and returned 1). On success, a
 * pointer to the first plaintext byte is returned, and *len is adjusted
 * to contain the plaintext length; on error, NULL is returned.
 *
 * The decryption engine is responsible for keeping track of the record
 * sequence number.
 */
typedef struct br_sslrec_in_class_ br_sslrec_in_class;
struct br_sslrec_in_class_ {
	size_t context_size;
	int (*check_length)(const br_sslrec_in_class *const *ctx,
		size_t record_len);
	unsigned char *(*decrypt)(const br_sslrec_in_class **ctx,
		int record_type, unsigned version,
		void *payload, size_t *len);
};

/*
 * The encryption engine for outgoing records is an object that implements
 * the following functions:
 *
 *   max_plaintext   get start and end offsets for payload
 *   encrypt         encrypt and apply MAC on current record
 *
 * The max_plaintext() function receives as inputs the start and end
 * of the buffer where the payload will be stored; this function assumes
 * that there will be room for a record header (5 bytes) BEFORE the
 * offset specified by *start. The max_plaintext() function then adjusts
 * the two offsets to designate the area for the plaintext.
 *
 * The encrypt() function assumes that the provided plaintext data is
 * in a buffer with enough room before and after the data chunk to
 * receive the needed headers (i.e. the plaintext is at offsets which
 * were computed by an earlier call to max_plaintext()). It returns
 * a pointer to the start of the encrypted record, and writes the
 * encrypted record length in '*len' (that length includes the record
 * header).
 *
 * The encryption engine MUST fill the record header. If the engine
 * performs a "split" into several records, then the successive records
 * MUST be consecutive in RAM; the returned length is thus the sum of
 * the individual record lengths.
 *
 * The encryption engine is responsible for keeping track of the record
 * sequence number.
 */
typedef struct br_sslrec_out_class_ br_sslrec_out_class;
struct br_sslrec_out_class_ {
	size_t context_size;
	void (*max_plaintext)(const br_sslrec_out_class *const *ctx,
		size_t *start, size_t *end);
	unsigned char *(*encrypt)(const br_sslrec_out_class **ctx,
		int record_type, unsigned version,
		void *plaintext, size_t *len);
};

/*
 * An outgoing no-encryption engine is defined, to process outgoing
 * records before completion of the initial handshake.
 */
typedef struct {
	const br_sslrec_out_class *vtable;
} br_sslrec_out_clear_context;
extern const br_sslrec_out_class br_sslrec_out_clear_vtable;

/* ===================================================================== */

/*
 * An engine for processing incoming records with a block cipher in
 * CBC mode has an extra initialization function, that takes as inputs:
 * -- a block cipher (CBC decryption) and its key;
 * -- a hash function for HMAC, with the MAC key and output length;
 * -- an optional initial IV.
 * If the IV is not provided (the 'iv' parameter is NULL), then the
 * engine will use an explicit per-record IV (as is mandated in TLS 1.1+).
 *
 * The initialization function is responsible for setting the 'vtable'
 * field of the context.
 */
typedef struct br_sslrec_in_cbc_class_ br_sslrec_in_cbc_class;
struct br_sslrec_in_cbc_class_ {
	br_sslrec_in_class inner;
	void (*init)(const br_sslrec_in_cbc_class **ctx,
		const br_block_cbcdec_class *bc_impl,
		const void *bc_key, size_t bc_key_len,
		const br_hash_class *dig_impl,
		const void *mac_key, size_t mac_key_len, size_t mac_out_len,
		const void *iv);
};

/*
 * An engine for processing outgoing records with a block cipher in
 * CBC mode has an extra initialization function, that takes as inputs:
 * -- a block cipher (CBC encryption) and its key;
 * -- a hash function for HMAC, with the MAC key and output length;
 * -- an optional initial IV.
 * If the IV is not provided (the 'iv' parameter is NULL), then the
 * engine will use an explicit per-record IV (as is mandated in TLS 1.1+).
 *
 * The initialization function is responsible for setting the 'vtable'
 * field of the context.
 */
typedef struct br_sslrec_out_cbc_class_ br_sslrec_out_cbc_class;
struct br_sslrec_out_cbc_class_ {
	br_sslrec_out_class inner;
	void (*init)(const br_sslrec_out_cbc_class **ctx,
		const br_block_cbcenc_class *bc_impl,
		const void *bc_key, size_t bc_key_len,
		const br_hash_class *dig_impl,
		const void *mac_key, size_t mac_key_len, size_t mac_out_len,
		const void *iv);
};

/*
 * Context structure for decrypting incoming records with CBC + HMAC.
 */
typedef struct {
	const br_sslrec_in_cbc_class *vtable;
	uint64_t seq;
	union {
		const br_block_cbcdec_class *vtable;
		br_aes_gen_cbcdec_keys aes;
		br_des_gen_cbcdec_keys des;
	} bc;
	br_hmac_key_context mac;
	size_t mac_len;
	unsigned char iv[16];
	int explicit_IV;
} br_sslrec_in_cbc_context;
extern const br_sslrec_in_cbc_class br_sslrec_in_cbc_vtable;

/*
 * Context structure for encrypting outgoing records with CBC + HMAC.
 */
typedef struct {
	const br_sslrec_out_cbc_class *vtable;
	uint64_t seq;
	union {
		const br_block_cbcenc_class *vtable;
		br_aes_gen_cbcenc_keys aes;
		br_des_gen_cbcenc_keys des;
	} bc;
	br_hmac_key_context mac;
	size_t mac_len;
	unsigned char iv[16];
	int explicit_IV;
} br_sslrec_out_cbc_context;
extern const br_sslrec_out_cbc_class br_sslrec_out_cbc_vtable;

/* ===================================================================== */

/*
 * An engine for processing incoming records with a block cipher in
 * GCM mode has an extra initialization function, that takes as inputs:
 * -- a block cipher (CTR) and its key;
 * -- a GHASH implementation;
 * -- an initial IV (4 bytes).
 *
 * The initialization function is responsible for setting the 'vtable'
 * field of the context.
 */
typedef struct br_sslrec_in_gcm_class_ br_sslrec_in_gcm_class;
struct br_sslrec_in_gcm_class_ {
	br_sslrec_in_class inner;
	void (*init)(const br_sslrec_in_gcm_class **ctx,
		const br_block_ctr_class *bc_impl,
		const void *key, size_t key_len,
		br_ghash gh_impl,
		const void *iv);
};

/*
 * An engine for processing outgoing records with a block cipher in
 * GCM mode has an extra initialization function, that takes as inputs:
 * -- a block cipher (CTR) and its key;
 * -- a GHASH implementation;
 * -- an initial IV (4 bytes).
 *
 * The initialization function is responsible for setting the 'vtable'
 * field of the context.
 */
typedef struct br_sslrec_out_gcm_class_ br_sslrec_out_gcm_class;
struct br_sslrec_out_gcm_class_ {
	br_sslrec_out_class inner;
	void (*init)(const br_sslrec_out_gcm_class **ctx,
		const br_block_ctr_class *bc_impl,
		const void *key, size_t key_len,
		br_ghash gh_impl,
		const void *iv);
};

/*
 * We use the same context structure for incoming and outgoing records
 * with GCM, because it allows internal code sharing.
 */
typedef struct {
	union {
		const void *gen;
		const br_sslrec_in_gcm_class *in;
		const br_sslrec_out_gcm_class *out;
	} vtable;
	uint64_t seq;
	union {
		const br_block_ctr_class *vtable;
		br_aes_gen_ctr_keys aes;
	} bc;
	br_ghash gh;
	unsigned char iv[4];
	unsigned char h[16];
} br_sslrec_gcm_context;

extern const br_sslrec_in_gcm_class br_sslrec_in_gcm_vtable;
extern const br_sslrec_out_gcm_class br_sslrec_out_gcm_vtable;

/* ===================================================================== */

/*
 * Type for session parameters, to be saved for session resumption.
 */
typedef struct {
	unsigned char session_id[32];
	unsigned char session_id_len;
	uint16_t version;
	uint16_t cipher_suite;
	unsigned char master_secret[48];
} br_ssl_session_parameters;

/*
 * Maximum numnber of cipher suites supported by a client or server.
 */
#define BR_MAX_CIPHER_SUITES   40

/*
 * Context structure for SSL engine. This is common to the client and
 * server; the engine manages records, including alerts, closures, and
 * transitions to new encryption/MAC algorithms. Processing of handshake
 * records is delegated to externally provided code. This structure
 * should not be used directly, but is meant to be included as first
 * field of the context structures for SSL clients and servers.
 */
typedef struct {

	/*
	 * The error code. When non-zero, then the state is "failed" and
	 * no I/O may occur until reset.
	 */
	int err;

	/*
	 * Configured I/O buffers. They are either disjoint, or identical.
	 */
	unsigned char *ibuf, *obuf;
	size_t ibuf_len, obuf_len;

	/*
	 * Maximum fragment length applies to outgoing records; incoming
	 * records can be processed as long as they fit in the input
	 * buffer. It is guaranteed that incoming records at least as big
	 * as max_frag_len can be processed.
	 */
	uint16_t max_frag_len;
	unsigned char log_max_frag_len;
	unsigned char peer_log_max_frag_len;

	/*
	 * Buffering management registers.
	 */
	size_t ixa, ixb, ixc;
	size_t oxa, oxb, oxc;
	unsigned char iomode;
	unsigned char incrypt;

	/*
	 * Shutdown flag: when set to non-zero, incoming record bytes
	 * will not be accepted anymore. This is used after a close_notify
	 * has been received: afterwards, the engine no longer claims that
	 * it could receive bytes from the transport medium.
	 */
	unsigned char shutdown_recv;

	/*
	 * 'record_type_in' is set to the incoming record type when the
	 * record header has been received.
	 * 'record_type_out' is used to make the next outgoing record
	 * header when it is ready to go.
	 */
	unsigned char record_type_in, record_type_out;

	/*
	 * When a record is received, its version is extracted:
	 * -- if 'version_in' is 0, then it is set to the received version;
	 * -- otherwise, if the received version is not identical to
	 *    the 'version_in' contents, then a failure is reported.
	 *
	 * This implements the SSL requirement that all records shall
	 * use the negotiated protocol version, once decided (in the
	 * ServerHello). It is up to the handshake handler to adjust this
	 * field when necessary.
	 */
	uint16_t version_in;

	/*
	 * 'version_out' is used when the next outgoing record is ready
	 * to go.
	 */
	uint16_t version_out;

	/*
	 * Record handler contexts.
	 */
	union {
		const br_sslrec_in_class *vtable;
		br_sslrec_in_cbc_context cbc;
		br_sslrec_gcm_context gcm;
	} in;
	union {
		const br_sslrec_out_class *vtable;
		br_sslrec_out_clear_context clear;
		br_sslrec_out_cbc_context cbc;
		br_sslrec_gcm_context gcm;
	} out;

	/*
	 * The "application data" flag. It is set when application data
	 * can be exchanged, cleared otherwise.
	 */
	unsigned char application_data;

	/*
	 * Context RNG.
	 */
	br_hmac_drbg_context rng;
	int rng_init_done;
	int rng_os_rand_done;

	/*
	 * Supported minimum and maximum versions, and cipher suites.
	 */
	uint16_t version_min;
	uint16_t version_max;
	uint16_t suites_buf[BR_MAX_CIPHER_SUITES];
	unsigned char suites_num;

	/*
	 * For clients, the server name to send as a SNI extension. For
	 * servers, the name received in the SNI extension (if any).
	 */
	char server_name[256];

	/*
	 * "Security parameters". These are filled by the handshake
	 * handler, and used when switching encryption state.
	 */
	unsigned char client_random[32];
	unsigned char server_random[32];
	/* obsolete
	unsigned char session_id[32];
	unsigned char session_id_len;
	uint16_t version;
	uint16_t cipher_suite;
	unsigned char master_secret[48];
	*/
	br_ssl_session_parameters session;

	/*
	 * ECDHE elements: curve and point from the peer. The server also
	 * uses that buffer for the point to send to the client.
	 */
	unsigned char ecdhe_curve;
	unsigned char ecdhe_point[133];
	unsigned char ecdhe_point_len;

	/*
	 * Secure renegotiation (RFC 5746): 'reneg' can be:
	 *   0   first handshake (server support is not known)
	 *   1   server does not support secure renegotiation
	 *   2   server supports secure renegotiation
	 *
	 * The saved_finished buffer contains the client and the
	 * server "Finished" values from the last handshake, in
	 * that order (12 bytes each).
	 */
	unsigned char reneg;
	unsigned char saved_finished[24];

	/*
	 * Context variables for the handshake processor.
	 * The 'pad' must be large enough to accommodate an
	 * RSA-encrypted pre-master secret, or a RSA signature on
	 * key exchange parameters; since we want to support up to
	 * RSA-4096, this means at least 512 bytes.
	 * (Other pad usages require its length to be at least 256.)
	 */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	unsigned char pad[512];
	unsigned char *hbuf_in, *hbuf_out, *saved_hbuf_out;
	size_t hlen_in, hlen_out;
	void (*hsrun)(void *ctx);

	/*
	 * The 'action' value communicates OOB information between the
	 * engine and the handshake processor.
	 *
	 * From the engine:
	 *   0  invocation triggered by I/O
	 *   1  invocation triggered by explicit close
	 *   2  invocation triggered by explicit renegotiation
	 */
	unsigned char action;

	/*
	 * State for alert messages. Value is either 0, or the value of
	 * the alert level byte (level is either 1 for warning, or 2 for
	 * fatal; we convert all other values to 'fatal').
	 */
	unsigned char alert;

	/*
	 * Closure flags. This flag is set when a close_notify has been
	 * received from the peer.
	 */
	unsigned char close_received;

	/*
	 * Multi-hasher for the handshake messages. The handshake handler
	 * is responsible for resetting it when appropriate.
	 */
	br_multihash_context mhash;

	/*
	 * Pointer to the X.509 engine. The engine is supposed to be
	 * already initialized. It is used to validate the peer's
	 * certificate.
	 */
	const br_x509_class **x509ctx;

	/*
	 * Pointers to implementations; left to NULL for unsupported
	 * functions. For the raw hash functions, implementations are
	 * referenced from the multihasher (mhash field).
	 */
	br_tls_prf_impl prf10;
	br_tls_prf_impl prf_sha256;
	br_tls_prf_impl prf_sha384;
	const br_block_cbcenc_class *iaes_cbcenc;
	const br_block_cbcdec_class *iaes_cbcdec;
	const br_block_ctr_class *iaes_ctr;
	const br_block_cbcenc_class *ides_cbcenc;
	const br_block_cbcdec_class *ides_cbcdec;
	br_ghash ighash;
	const br_sslrec_in_cbc_class *icbc_in;
	const br_sslrec_out_cbc_class *icbc_out;
	const br_sslrec_in_gcm_class *igcm_in;
	const br_sslrec_out_gcm_class *igcm_out;
	const br_ec_impl *iec;

} br_ssl_engine_context;

/*
 * Set the minimum and maximum supported protocol versions.
 */
static inline void
br_ssl_engine_set_versions(br_ssl_engine_context *cc,
	unsigned version_min, unsigned version_max)
{
	cc->version_min = version_min;
	cc->version_max = version_max;
}

/*
 * Set the list of cipher suites advertised by this context. The provided
 * array is copied into the context. It is the caller responsibility
 * to ensure that all provided suites will be supported by the context.
 */
void br_ssl_engine_set_suites(br_ssl_engine_context *cc,
	const uint16_t *suites, size_t suites_num);

/*
 * Set the X.509 engine. The context should be already initialized and
 * ready to process a new chain.
 */
static inline void
br_ssl_engine_set_x509(br_ssl_engine_context *cc, const br_x509_class **x509ctx)
{
	cc->x509ctx = x509ctx;
}

/*
 * Set a hash function implementation (by ID).
 */
static inline void
br_ssl_engine_set_hash(br_ssl_engine_context *ctx,
	int id, const br_hash_class *impl)
{
	br_multihash_setimpl(&ctx->mhash, id, impl);
}

/*
 * Get a hash function implementation (by ID).
 */
static inline const br_hash_class *
br_ssl_engine_get_hash(br_ssl_engine_context *ctx, int id)
{
	return br_multihash_getimpl(&ctx->mhash, id);
}

/*
 * Set the PRF implementation (for TLS 1.0 and 1.1).
 */
static inline void
br_ssl_engine_set_prf10(br_ssl_engine_context *cc, br_tls_prf_impl impl)
{
	cc->prf10 = impl;
}

/*
 * Set the PRF implementation (for TLS 1.2, with SHA-256).
 */
static inline void
br_ssl_engine_set_prf_sha256(br_ssl_engine_context *cc, br_tls_prf_impl impl)
{
	cc->prf_sha256 = impl;
}

/*
 * Set the PRF implementation (for TLS 1.2, with SHA-384).
 */
static inline void
br_ssl_engine_set_prf_sha384(br_ssl_engine_context *cc, br_tls_prf_impl impl)
{
	cc->prf_sha384 = impl;
}

/*
 * Set the AES/CBC implementations.
 */
static inline void
br_ssl_engine_set_aes_cbc(br_ssl_engine_context *cc,
	const br_block_cbcenc_class *impl_enc,
	const br_block_cbcdec_class *impl_dec)
{
	cc->iaes_cbcenc = impl_enc;
	cc->iaes_cbcdec = impl_dec;
}

/*
 * Set the AES/CTR implementation.
 */
static inline void
br_ssl_engine_set_aes_ctr(br_ssl_engine_context *cc,
	const br_block_ctr_class *impl)
{
	cc->iaes_ctr = impl;
}

/*
 * Set the 3DES/CBC implementations.
 */
static inline void
br_ssl_engine_set_des_cbc(br_ssl_engine_context *cc,
	const br_block_cbcenc_class *impl_enc,
	const br_block_cbcdec_class *impl_dec)
{
	cc->ides_cbcenc = impl_enc;
	cc->ides_cbcdec = impl_dec;
}

/*
 * Set the GHASH implementation (for GCM).
 */
static inline void
br_ssl_engine_set_ghash(br_ssl_engine_context *cc, br_ghash impl)
{
	cc->ighash = impl;
}

/*
 * Set the CBC+HMAC record processor implementations.
 */
static inline void
br_ssl_engine_set_cbc(br_ssl_engine_context *cc,
	const br_sslrec_in_cbc_class *impl_in,
	const br_sslrec_out_cbc_class *impl_out)
{
	cc->icbc_in = impl_in;
	cc->icbc_out = impl_out;
}

/*
 * Set the GCM record processor implementations.
 */
static inline void
br_ssl_engine_set_gcm(br_ssl_engine_context *cc,
	const br_sslrec_in_gcm_class *impl_in,
	const br_sslrec_out_gcm_class *impl_out)
{
	cc->igcm_in = impl_in;
	cc->igcm_out = impl_out;
}

/*
 * Set the ECC core operations implementation. The 'iec' parameter
 * points to the core EC code used for both ECDHE and ECDSA.
 */
static inline void
br_ssl_engine_set_ec(br_ssl_engine_context *cc, const br_ec_impl *iec)
{
	cc->iec = iec;
}

/*
 * Set the I/O buffer for a SSL engine. Once this call has been made,
 * br_ssl_client_reset() or br_ssl_server_reset() must be called before
 * using the context.
 *
 * If 'bidi' is 1, then the buffer will be internally split to support
 * concurrent input and output; otherwise, the caller will be responsible
 * for reading all buffered incoming data before writing. The latter
 * case makes support of HTTPS pipelining difficult, thus bidirectional
 * buffering is recommended if the RAM can be spared.
 *
 * The BR_SSL_BUFSIZE_MONO and BR_SSL_BUFSIZE_BIDI macros yield optimal
 * buffer sizes for the monodirectional and bidirectional cases,
 * respectively. If using optimal sizes (or larger), then records with
 * the maximum length supported by the TLS standard will be accepted
 * and emitted.
 */
void br_ssl_engine_set_buffer(br_ssl_engine_context *cc,
	void *iobuf, size_t iobuf_len, int bidi);

/*
 * Set the I/O buffers for a SSL engine. This call sets two buffers, for
 * concurrent input and output. The two buffers MUST be disjoint. Once
 * this call has been made, br_ssl_client_reset() or
 * br_ssl_server_reset() must be called before using the context.
 *
 * The BR_SSL_BUFSIZE_INPUT and BR_SSL_BUFSIZE_OUTPUT macros evaluate to
 * optimal sizes for the input and output buffers, respectively. If
 * using optimal sizes (or larger), then records with the maximum length
 * supported by the TLS standard will be accepted and emitted.
 */
void br_ssl_engine_set_buffers_bidi(br_ssl_engine_context *cc,
	void *ibuf, size_t ibuf_len, void *obuf, size_t obuf_len);

/*
 * Inject some "initial entropy" in the context. This entropy will be added
 * to what can be obtained from the underlying operating system, if that
 * OS is supported.
 *
 * This function may be called several times; all injected entropy chunks
 * are cumulatively mixed.
 *
 * If entropy gathering from the OS is supported and compiled in, then this
 * step is optional. Otherwise, it is mandatory to inject randomness, and
 * the caller MUST take care to push (as one or several successive calls)
 * enough entropy to achieve cryptographic resistance (at least 80 bits,
 * preferably 128 or more). The engine will report an error if no entropy
 * was provided and none can be obtained from the OS.
 *
 * Take care that this function cannot assess the cryptographic quality of
 * the provided bytes.
 *
 * In all generality, "entropy" must here be considered to mean "that
 * which the attacker cannot predict". If your OS/architecture does not
 * have a suitable source of randomness, then you can make do with the
 * combination of a large enough secret value (possibly a copy of an
 * asymmetric private key that you also store on the system) AND a
 * non-repeating value (e.g. current time, provided that the local clock
 * cannot be reset or altered by the attacker).
 */
void br_ssl_engine_inject_entropy(br_ssl_engine_context *cc,
	const void *data, size_t len);

/*
 * Get the "server name" in this engine. For clients, this is the name
 * provided with br_ssl_client_reset(); for servers, this is the name
 * received from the client as part of the ClientHello message. If there
 * is no such name (e.g. the client did not send an SNI extension) then
 * the returned string is empty (returned pointer points to a byte of
 * value 0).
 */
static inline const char *
br_ssl_engine_get_server_name(br_ssl_engine_context *cc)
{
	return cc->server_name;
}

/*
 * An SSL engine (client or server) has, at any time, a state which is
 * the combination of zero, one or more of these flags:
 *
 *   BR_SSL_CLOSED    engine is finished, no more I/O (until next reset)
 *   BR_SSL_SENDREC   engine has some bytes to send to the peer
 *   BR_SSL_RECVREC   engine expects some bytes from the peer
 *   BR_SSL_SENDAPP   engine may receive application data to send (or flush)
 *   BR_SSL_RECVAPP   engine has obtained some application data from the peer,
 *                    that should be read by the caller
 *
 * If no flag at all is set (state value is 0), then the engine is not
 * fully initialized yet.
 *
 * The BR_SSL_CLOSED flag is exclusive; when it is set, no other flag is set.
 * To distinguish between a normal closure and an error, use
 * br_ssl_engine_last_error().
 *
 * Generally speaking, BR_SSL_SENDREC and BR_SSL_SENDAPP are mutually
 * exclusive: the input buffer, at any point, either accumulates
 * plaintext data, or contains an assembled record that is being sent.
 * Similarly, BR_SSL_RECVREC and BR_SSL_RECVAPP are mutually exclusive.
 * This may change in a future library version.
 */

#define BR_SSL_CLOSED    0x0001
#define BR_SSL_SENDREC   0x0002
#define BR_SSL_RECVREC   0x0004
#define BR_SSL_SENDAPP   0x0008
#define BR_SSL_RECVAPP   0x0010

/*
 * Get the current engine state.
 */
unsigned br_ssl_engine_current_state(const br_ssl_engine_context *cc);

/*
 * Get the engine error indicator. This is BR_ERR_OK (0) if no error was
 * encountered since the last call to br_ssl_client_reset() or
 * br_ssl_server_reset(). Only these calls clear the error indicator.
 */
static inline int
br_ssl_engine_last_error(const br_ssl_engine_context *cc)
{
	return cc->err;
}

/*
 * There are four I/O operations, each identified by a symbolic name:
 *
 *   sendapp   inject application data in the engine
 *   recvapp   retrieving application data from the engine
 *   sendrec   sending records on the transport medium
 *   recvrec   receiving records from the transport medium
 *
 * Terminology works thus: in a layered model where the SSL engine sits
 * between the application and the network, "send" designates operations
 * where bytes flow from application to network, and "recv" for the
 * reverse operation. Application data (the plaintext that is to be
 * conveyed through SSL) is "app", while encrypted records are "rec".
 * Note that from the SSL engine point of view, "sendapp" and "recvrec"
 * designate bytes that enter the engine ("inject" operation), while
 * "recvapp" and "sendrec" designate bytes that exit the engine
 * ("extract" operation).
 *
 * For the operation 'xxx', two functions are defined:
 *
 *   br_ssl_engine_xxx_buf
 *      Returns a pointer and length to the buffer to use for that
 *      operation. '*len' is set to the number of bytes that may be read
 *      from the buffer (extract operation) or written to the buffer
 *      (inject operation). If no byte may be exchanged for that operation
 *      at that point, then '*len' is set to zero, and NULL is returned.
 *      The engine state is unmodified by this call.
 *
 *   br_ssl_engine_xxx_ack
 *      Informs the engine that 'len' bytes have been read from the buffer
 *      (extract operation) or written to the buffer (inject operation).
 *      The 'len' value MUST NOT be zero. The 'len' value MUST NOT exceed
 *      that which was obtained from a preceeding br_ssl_engine_xxx_buf()
 *      call.
 */

unsigned char *br_ssl_engine_sendapp_buf(
	const br_ssl_engine_context *cc, size_t *len);
void br_ssl_engine_sendapp_ack(br_ssl_engine_context *cc, size_t len);

unsigned char *br_ssl_engine_recvapp_buf(
	const br_ssl_engine_context *cc, size_t *len);
void br_ssl_engine_recvapp_ack(br_ssl_engine_context *cc, size_t len);

unsigned char *br_ssl_engine_sendrec_buf(
	const br_ssl_engine_context *cc, size_t *len);
void br_ssl_engine_sendrec_ack(br_ssl_engine_context *cc, size_t len);

unsigned char *br_ssl_engine_recvrec_buf(
	const br_ssl_engine_context *cc, size_t *len);
void br_ssl_engine_recvrec_ack(br_ssl_engine_context *cc, size_t len);

/*
 * If some application data has been buffered in the engine, then wrap
 * it into a record and mark it for sending. If no application data has
 * been buffered but the engine would be ready to accept some, AND the
 * 'force' parameter is non-zero, then an empty record is assembled and
 * marked for sending. In all other cases, this function does nothing.
 *
 * Empty records are technically legal, but not all existing SSL/TLS
 * implementations support them. Empty records can be useful as a
 * transparent "keep-alive" mechanism to maintain some low-level
 * network activity.
 */
void br_ssl_engine_flush(br_ssl_engine_context *cc, int force);

/*
 * Close the context. If, at that point, the context is open and in
 * ready state, then a close_notify alert is assembled and marked for
 * sending. Otherwise, no such alert is assembled.
 */
void br_ssl_engine_close(br_ssl_engine_context *cc);

/*
 * Initiate a renegotiation. If the engine is failed or closed, or if
 * the peer is known not to support secure renegotiation (RFC 5746),
 * then this function returns 0. Otherwise, this function returns 1 and
 * a renegotiation attempt is triggered, unless a handshake is already
 * taking place, in which case the call is ignored.
 */
int br_ssl_engine_renegotiate(br_ssl_engine_context *cc);

/*
 * Context structure for a SSL client.
 */
typedef struct {
	/*
	 * The encapsulated engine context.
	 */
	br_ssl_engine_context eng;

	/*
	 * Minimum ClientHello length; padding with an extension (RFC
	 * 7685) is added if necessary to match at least that length.
	 * Such padding is nominally unnecessary, but it has been used
	 * to work around some server implementation bugs.
	 */
	uint16_t min_clienthello_len;

	/*
	 * Implementations.
	 */
	br_rsa_public irsapub;
	br_rsa_pkcs1_vrfy irsavrfy;
	br_ecdsa_vrfy iecdsa;

} br_ssl_client_context;

/*
 * Each br_ssl_client_init_xxx() function sets the list of supported
 * cipher suites and used implementations, as specified by the profile
 * name 'xxx'. Defined profile names are:
 *
 *    full    all supported versions and suites; constant-time implementations
 *    FIXME: add other profiles
 */

void br_ssl_client_init_full(br_ssl_client_context *cc,
	br_x509_minimal_context *xc,
	const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num);

/*
 * Clear the complete contents of a SSL client context, including the
 * reference to the configured buffer, implementations, cipher suites
 * and state.
 */
void br_ssl_client_zero(br_ssl_client_context *cc);

/*
 * Set the RSA public-key operations implementation. This will be used
 * to encrypt the pre-master secret with the server's RSA public key
 * (RSA-encryption cipher suites only).
 */
static inline void
br_ssl_client_set_rsapub(br_ssl_client_context *cc, br_rsa_public irsapub)
{
	cc->irsapub = irsapub;
}

/*
 * Set the RSA signature verification implementation. This will be used
 * to verify the server's signature on its ServerKeyExchange message
 * (ECDHE_RSA cipher suites only).
 */
static inline void
br_ssl_client_set_rsavrfy(br_ssl_client_context *cc, br_rsa_pkcs1_vrfy irsavrfy)
{
	cc->irsavrfy = irsavrfy;
}

/*
 * Set the ECDSA implementation (signature verification). The ECC core
 * implementation must also have been set.
 */
static inline void
br_ssl_client_set_ecdsa(br_ssl_client_context *cc, br_ecdsa_vrfy iecdsa)
{
	cc->iecdsa = iecdsa;
}

/*
 * Set the minimum ClientHello length (RFC 7685 padding).
 */
static inline void
br_ssl_client_set_min_clienthello_len(br_ssl_client_context *cc, uint16_t len)
{
	cc->min_clienthello_len = len;
}

/*
 * Prepare or reset a client context for connecting with a server of
 * name 'server_name'. The 'server_name' parameter is used to fill the
 * SNI extension; if the parameter is NULL then no SNI extension will
 * be sent.
 *
 * If 'resume_session' is non-zero and the context was previously used
 * then the session parameters may be reused (depending on whether the
 * server previously sent a non-empty session ID, and accepts the session
 * resumption).
 *
 * On failure, the context is marked as failed, and this function
 * returns 0. A possible failure condition is when no initial entropy
 * was injected, and none could be obtained from the OS (either OS
 * randomness gathering is not supported, or it failed).
 */
int br_ssl_client_reset(br_ssl_client_context *cc,
	const char *server_name, int resume_session);

/*
 * Forget any session in the context. This means that the next handshake
 * that uses this context will necessarily be a full handshake (this
 * applies both to new connections and to renegotiations).
 */
static inline void
br_ssl_client_forget_session(br_ssl_client_context *cc)
{
	cc->eng.session.session_id_len = 0;
}

/*
 * Type for a "translated cipher suite", as an array of 16-bit integers:
 * first element is the cipher suite identifier (as used on the wire),
 * and the second element is the concatenation of four 4-bit elements which
 * characterise the cipher suite contents. In most to least significant
 * order, these 4-bit elements are:
 *
 *   Bits 12 to 15: key exchange + server key type
 *      0   RSA            RSA key exchange, key is RSA (encryption)
 *      1   ECDHE-RSA      ECDHE key exchange, key is RSA (signature)
 *      2   ECDHE-ECDSA    ECDHE key exchange, key is EC (signature)
 *      3   ECDH-RSA       Key is EC (key exchange), cert is signed with RSA
 *      4   ECDH-ECDSA     Key is EC (key exchange), cert is signed with ECDSA
 *
 *   Bits 8 to 11: symmetric encryption algorithm
 *      0   3DES/CBC
 *      1   AES-128/CBC
 *      2   AES-256/CBC
 *      3   AES-128/GCM
 *      4   AES-256/GCM
 *      5   ChaCha20/Poly1305
 *
 *   Bits 4 to 7: MAC algorithm
 *      0   AEAD           No dedicated MAC because encryption is AEAD
 *      2   HMAC/SHA-1     Value matches br_sha1_ID
 *      4   HMAC/SHA-256   Value matches br_sha256_ID
 *      5   HMAC/SHA-384   Value matches br_sha384_ID
 *
 *   Bits 0 to 3: hash function for PRF when used with TLS-1.2
 *      4   SHA-256        Value matches br_sha256_ID
 *      5   SHA-384        Value matches br_sha384_ID
 */
typedef uint16_t br_suite_translated[2];

#define BR_SSLKEYX_RSA           0
#define BR_SSLKEYX_ECDHE_RSA     1
#define BR_SSLKEYX_ECDHE_ECDSA   2
#define BR_SSLKEYX_ECDH_RSA      3
#define BR_SSLKEYX_ECDH_ECDSA    4

#define BR_SSLENC_3DES_CBC       0
#define BR_SSLENC_AES128_CBC     1
#define BR_SSLENC_AES256_CBC     2
#define BR_SSLENC_AES128_GCM     3
#define BR_SSLENC_AES256_GCM     4
#define BR_SSLENC_CHACHA20       5

#define BR_SSLMAC_AEAD           0
#define BR_SSLMAC_SHA1           br_sha1_ID
#define BR_SSLMAC_SHA256         br_sha256_ID
#define BR_SSLMAC_SHA384         br_sha384_ID

#define BR_SSLPRF_SHA256         br_sha256_ID
#define BR_SSLPRF_SHA384         br_sha384_ID

/*
 * Pre-declaration for the SSL server context.
 */
typedef struct br_ssl_server_context_ br_ssl_server_context;

/*
 * Type for the server policy choices, taken after analysis of the client
 * message:
 *
 *     cipher_suite   Cipher suite to use.
 *
 *     hash_id        Signature hash function identifier (hash function
 *                    to use for signing the ServerKeyExchange, when the
 *                    suite uses ECDHE).
 *
 *     chain          The certificate chain to send (number of certificates
 *     chain_len      is in chain_length). The certificates are send "as is"
 *                    and shall be in standard SSL/TLS order (i.e. end-entity
 *                    first, each subsequent certificate signs the previous).
 */
typedef struct {
	uint16_t cipher_suite;
	int hash_id;
	const br_x509_certificate *chain;
	size_t chain_len;
} br_ssl_server_choices;

/*
 * Type for the certificate and private key handler on the server: an
 * object with the following methods:
 *
 *   choose    Select the parameters for this connection (cipher suite,
 *             certificate chain...). The selection is written into the
 *             '*choices' structure. Returned value is 1 on success, or
 *             0 on error (an error here means that the handshake will
 *             fail, and a handshake_failure alert will be sent to the
 *             client).
 *
 *   do_keyx   Perform the server-side key exchange operation. Returned
 *             value is 1 on success, 0 on error (see below). This is
 *             called only when the selected cipher suite calls for a
 *             RSA or ECDH key exchange involving the server key.
 *
 *   do_sign   Perform the server-side signature operation. Returned
 *             value is the signature length, or 0 on error (see below).
 *             This is called only when the selected cipher suite calls
 *             for an ECDHE key exchange, signed by the server with its key.
 *
 *
 * The do_keyx() method shall apply the following semantics:
 *
 * -- For RSA key exchange, it shall decrypt the incoming data along
 * the rules of PKCS#1 v1.5. The method must verify the proper padding
 * and also that the decrypted message length is exactly 48 bytes.
 * IMPORTANT: these operations MUST be constant-time (or adequatly blinded).
 * The decrypted message is written in the first 48 bytes of data[]. The
 * caller makes sure that the data[] buffer is large enough, and that 'len'
 * is at least 59 bytes.
 *
 * -- For ECDH key exchange, the provided data is an EC point (uncompressed
 * format); the method shall multiply that point with the server private
 * key, and write the X coordinate of the resulting point in the data[]
 * buffer, starting at offset 1 (so if the method produces a compressed or
 * uncompressed point, form offset 0, then everything is fine).
 *
 * In both cases, returned value is 1 on success, 0 on error.
 *
 *
 * The do_sign() method shall compute the signature on the hash value
 * provided in the data[] buffer. The 'hv_len' value contains the hash
 * value length, while the 'len' parameter is the total size of the
 * buffer. The method must verify that the signature length is no more
 * than 'len' bytes, and report an error otherwise.
 *
 * The hash identifier is either 0 for the MD5+SHA-1 method in TLS-1.0 and
 * 1.1, or a non-zero hash function identifier in TLS-1.2 and later. In
 * the MD5+SHA-1 method, the hash value has length 36 bytes and there is
 * no hash function identifying header to add in the padding.
 *
 * Returned value is the signature length (in bytes). On error, this method
 * shall return 0.
 */
typedef struct br_ssl_server_policy_class_ br_ssl_server_policy_class;
struct br_ssl_server_policy_class_ {
	size_t context_size;
	int (*choose)(const br_ssl_server_policy_class **pctx,
		const br_ssl_server_context *cc,
		br_ssl_server_choices *choices);
	uint32_t (*do_keyx)(const br_ssl_server_policy_class **pctx,
		unsigned char *data, size_t len);
	size_t (*do_sign)(const br_ssl_server_policy_class **pctx,
		int hash_id, size_t hv_len, unsigned char *data, size_t len);
};

/*
 * A single-chain RSA policy handler, that always uses a single chain and
 * a RSA key. It may be restricted to do only signatures or only key
 * exchange.
 */
typedef struct {
	const br_ssl_server_policy_class *vtable;
	const br_x509_certificate *chain;
	size_t chain_len;
	const br_rsa_private_key *sk;
	unsigned allowed_usages;
	br_rsa_private irsacore;
	br_rsa_pkcs1_sign irsasign;
} br_ssl_server_policy_rsa_context;

/*
 * A single-chain EC policy handler, that always uses a single chain and
 * an EC key. It may be restricted to do only signatures or only key
 * exchange.
 */
typedef struct {
	const br_ssl_server_policy_class *vtable;
	const br_x509_certificate *chain;
	size_t chain_len;
	const br_ec_private_key *sk;
	unsigned allowed_usages;
	unsigned cert_issuer_key_type;
	const br_multihash_context *mhash;
	const br_ec_impl *iec;
	br_ecdsa_sign iecdsa;
} br_ssl_server_policy_ec_context;

/*
 * Class type for a session parameter cache.
 *
 *  save   Record session parameters. The session ID has been randomly
 *         generated, and the session ID length is always 32 bytes.
 *         The method shall copy the provided information (the structure
 *         is transient).
 *
 *  load   Find session parameters by ID. The session ID is in the relevant
 *         field in the '*params' structure, and has always length exactly
 *         32 bytes. The method shall fill in the other field with the
 *         session data, if found. Returned value is 1 when the session was
 *         found, 0 otherwise.
 *
 * Note that the requesting server context is provided. Implementations
 * may used some of the resources of that context, e.g. random number
 * generator or implementations of some cryptographic algorithms.
 */
typedef struct br_ssl_session_cache_class_ br_ssl_session_cache_class;
struct br_ssl_session_cache_class_ {
	size_t context_size;
	void (*save)(const br_ssl_session_cache_class **ctx,
		br_ssl_server_context *server_ctx,
		const br_ssl_session_parameters *params);
	int (*load)(const br_ssl_session_cache_class **ctx,
		br_ssl_server_context *server_ctx,
		br_ssl_session_parameters *params);
};

/*
 * Context for a very basic cache system that uses a linked list, managed
 * with an LRU algorithm (when the cache is full and a new set of parameters
 * must be saved, the least recently used entry is evicted). The storage
 * buffer is externally provided. Internally, an index tree is used to
 * speed up operations.
 */
typedef struct {
	const br_ssl_session_cache_class *vtable;
	unsigned char *store;
	size_t store_len, store_ptr;
	unsigned char index_key[32];
	const br_hash_class *hash;
	int init_done;
	uint32_t head, tail, root;
} br_ssl_session_cache_lru;

/*
 * Initialise a LRU session cache with the provided storage space.
 */
void br_ssl_session_cache_lru_init(br_ssl_session_cache_lru *cc,
	unsigned char *store, size_t store_len);

/*
 * Context structure for a SSL server.
 */
struct br_ssl_server_context_ {
	/*
	 * The encapsulated engine context.
	 */
	br_ssl_engine_context eng;

	/*
	 * Flags.
	 */
	uint32_t flags;

	/*
	 * Maximum version from the client.
	 */
	uint16_t client_max_version;

	/*
	 * Session cache.
	 */
	const br_ssl_session_cache_class **cache_vtable;

	/*
	 * Translated cipher suites supported by the client. The list
	 * is trimmed to include only the cipher suites that the
	 * server also supports; they are in the same order as in the
	 * client message.
	 */
	br_suite_translated client_suites[BR_MAX_CIPHER_SUITES];
	unsigned char client_suites_num;

	/*
	 * Hash functions supported by the client, with ECDSA and RSA
	 * (bit mask). For hash function with id 'x', set bit index is
	 * x for RSA, x+8 for ECDSA.
	 */
	uint16_t hashes;

	/*
	 * Curves supported by the client (bit mask, for named curves).
	 */
	uint32_t curves;

	/*
	 * Context for chain handler.
	 */
	const br_ssl_server_policy_class **policy_vtable;
	const br_x509_certificate *chain;
	size_t chain_len;
	const unsigned char *cert_cur;
	size_t cert_len;
	unsigned char sign_hash_id;

	/*
	 * For the core handlers, thus avoiding (in most cases) the
	 * need for an externally provided policy context.
	 */
	union {
		const br_ssl_server_policy_class *vtable;
		br_ssl_server_policy_rsa_context single_rsa;
		br_ssl_server_policy_ec_context single_ec;
	} chain_handler;

	/*
	 * Buffer for the ECDHE private key.
	 */
	unsigned char ecdhe_key[70];
	size_t ecdhe_key_len;

	/*
	 * Server-specific implementations.
	 */
};

/*
 * Get currently defined server behavioural flags.
 */
static inline uint32_t
br_ssl_server_get_flags(br_ssl_server_context *cc)
{
	return cc->flags;
}

/*
 * Set all server flags. Flags which are not in the 'flags' argument
 * are cleared.
 */
static inline void
br_ssl_server_set_all_flags(br_ssl_server_context *cc, uint32_t flags)
{
	cc->flags = flags;
}

/*
 * Add some server flags. The provided flags are set in the server context,
 * but other flags are untouched.
 */
static inline void
br_ssl_server_add_flags(br_ssl_server_context *cc, uint32_t flags)
{
	cc->flags |= flags;
}

/*
 * Remove some server flags. The provided flags are cleared from the
 * server context, but other flags are untouched.
 */
static inline void
br_ssl_server_remove_flags(br_ssl_server_context *cc, uint32_t flags)
{
	cc->flags &= ~flags;
}

/*
 * If this flag is set, then the server will enforce its own cipher suite
 * preference order; otherwise, it follows the client preferences.
 */
#define BR_OPT_ENFORCE_SERVER_PREFERENCES      ((uint32_t)1 << 0)

/*
 * Each br_ssl_server_init_xxx() function sets the list of supported
 * cipher suites and used implementations, as specified by the profile
 * name 'xxx'. Defined profile names are:
 *
 *    full_rsa    all supported algorithm, server key type is RSA
 *    full_ec     all supported algorithm, server key type is EC
 *    FIXME: add other profiles
 *
 * Naming scheme for "minimal" profiles: min123
 *
 * -- character 1: key exchange
 *      r = RSA
 *      e = ECDHE_RSA
 *      f = ECDHE_ECDSA
 *      u = ECDH_RSA
 *      v = ECDH_ECDSA
 * -- character 2: version / PRF
 *      0 = TLS 1.0 / 1.1 with MD5+SHA-1
 *      2 = TLS 1.2 with SHA-256
 *      3 = TLS 1.2 with SHA-384
 * -- character 3: encryption
 *      a = AES/CBC
 *      g = AES/GCM
 *      d = 3DES/CBC
 */

void br_ssl_server_init_full_rsa(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_rsa_private_key *sk);

void br_ssl_server_init_full_ec(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	unsigned cert_issuer_key_type, const br_ec_private_key *sk);

void br_ssl_server_init_minr2g(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_rsa_private_key *sk);
void br_ssl_server_init_mine2g(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_rsa_private_key *sk);
void br_ssl_server_init_minf2g(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_ec_private_key *sk);
void br_ssl_server_init_minu2g(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_ec_private_key *sk);
void br_ssl_server_init_minv2g(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_len,
	const br_ec_private_key *sk);

/*
 * Get the supported client suites. The returned array is ordered by
 * client or server preferences, depending on the relevant flag.
 */
static inline const br_suite_translated *
br_ssl_server_get_client_suites(const br_ssl_server_context *cc, size_t *num)
{
	*num = cc->client_suites_num;
	return cc->client_suites;
}

/*
 * Get the hash functions supported by the client. This is a field of
 * bits: for hash function of ID x, bit x is set if the hash function
 * is supported in RSA signatures, 8+x if it is supported with ECDSA.
 */
static inline uint16_t
br_ssl_server_get_client_hashes(const br_ssl_server_context *cc)
{
	return cc->hashes;
}

/*
 * Get the elliptic curves supported by the client. This is a bit field
 * (bit x is set if curve of ID x is supported).
 */
static inline uint32_t
br_ssl_server_get_client_curves(const br_ssl_server_context *cc)
{
	return cc->curves;
}

/*
 * Clear the complete contents of a SSL server context, including the
 * reference to the configured buffer, implementations, cipher suites
 * and state.
 */
void br_ssl_server_zero(br_ssl_server_context *cc);

/*
 * Set an externally provided policy context.
 */
static inline void
br_ssl_server_set_policy(br_ssl_server_context *cc,
	const br_ssl_server_policy_class **pctx)
{
	cc->policy_vtable = pctx;
}

/*
 * Set the server certificate chain and key (single RSA case).
 * The 'allowed_usages' is a combination of usages, namely
 * BR_KEYTYPE_KEYX and/or BR_KEYTYPE_SIGN.
 */
void br_ssl_server_set_single_rsa(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_length,
	const br_rsa_private_key *sk, unsigned allowed_usages,
	br_rsa_private irsacore, br_rsa_pkcs1_sign irsasign);

/*
 * Set the server certificate chain and key (single EC case).
 * The 'allowed_usages' is a combination of usages, namely
 * BR_KEYTYPE_KEYX and/or BR_KEYTYPE_SIGN.
 */
void br_ssl_server_set_single_ec(br_ssl_server_context *cc,
	const br_x509_certificate *chain, size_t chain_length,
	const br_ec_private_key *sk, unsigned allowed_usages,
	unsigned cert_issuer_key_type,
	const br_ec_impl *iec, br_ecdsa_sign iecdsa);

/*
 * Configure the server context to use the provided cache for session
 * parameters.
 */
static inline void
br_ssl_server_set_cache(br_ssl_server_context *cc,
	const br_ssl_session_cache_class **vtable)
{
	cc->cache_vtable = vtable;
}

/*
 * Prepare or reset a server context for handling an incoming client.
 */
int br_ssl_server_reset(br_ssl_server_context *cc);

/* ===================================================================== */

/*
 * Context for the simplified I/O context. The transport medium is accessed
 * through the low_read() and low_write() callback functions, each with
 * its own opaque context pointer.
 *
 *  low_read()    read some bytes, at most 'len' bytes, into data[]. The
 *                returned value is the number of read bytes, or -1 on error.
 *                The 'len' parameter is guaranteed never to exceed 20000,
 *                so the length always fits in an 'int' on all platforms.
 *
 *  low_write()   write up to 'len' bytes, to be read from data[]. The
 *                returned value is the number of written bytes, or -1 on
 *                error. The 'len' parameter is guaranteed never to exceed
 *                20000, so the length always fits in an 'int' on all
 *                parameters.
 *
 * A socket closure (if the transport medium is a socket) should be reported
 * as an error (-1). The callbacks shall endeavour to block until at least
 * one byte can be read or written; a callback returning 0 at times is
 * acceptable, but this normally leads to the callback being immediately
 * called again, so the callback should at least always try to block for
 * some time if no I/O can take place.
 *
 * The SSL engine naturally applies some buffering, so the callbacks need
 * not apply buffers of their own.
 */
typedef struct {
	br_ssl_engine_context *engine;
	int (*low_read)(void *read_context,
		unsigned char *data, size_t len);
	void *read_context;
	int (*low_write)(void *write_context,
		const unsigned char *data, size_t len);
	void *write_context;
} br_sslio_context;

/*
 * Initialise a simplified I/O context over the provided engine and
 * I/O callbacks.
 */
void br_sslio_init(br_sslio_context *ctx,
	br_ssl_engine_context *engine,
	int (*low_read)(void *read_context,
		unsigned char *data, size_t len),
	void *read_context,
	int (*low_write)(void *write_context,
		const unsigned char *data, size_t len),
	void *write_context);

/*
 * Read some application data from a SSL connection. This call returns
 * only when at least one byte has been obtained. Returned value is
 * the number of bytes read, or -1 on error. The number of bytes
 * always fits on an 'int' (data from a single SSL/TLS record is
 * returned).
 *
 * On error or SSL closure, this function returns -1. The caller should
 * inspect the error status on the SSL engine to distinguish between
 * normal closure and error.
 */
int br_sslio_read(br_sslio_context *cc, void *dst, size_t len);

/*
 * Read some application data from a SSL connection. This call returns
 * only when ALL requested bytes have been read. Returned value is 0
 * on success, -1 on error. A normal SSL closure before that many bytes
 * are obtained is reported as an error by this function.
 */
int br_sslio_read_all(br_sslio_context *cc, void *dst, size_t len);

/*
 * Write some application data onto a SSL connection. This call returns
 * only when at least one byte had been written onto the connection (but
 * not necessarily flushed). Returned value is the number of written
 * bytes, or -1 on error (error conditions include a closed connection).
 * It is guaranteed that the number of bytes written by such a call will
 * fit in an 'int' on all architectures.
 *
 * Note that some written bytes may be buffered; use br_sslio_flush()
 * to make sure that the data is sent to the transport stream.
 */
int br_sslio_write(br_sslio_context *cc, const void *src, size_t len);

/*
 * Write some application data onto a SSL connection. This call returns
 * only when ALL the bytes have been written onto the connection (but
 * not necessarily flushed). Returned value is 0 on success, -1 on error.
 * 
 * Note that some written bytes may be buffered; use br_sslio_flush()
 * to make sure that the data is sent to the transport stream.
 */
int br_sslio_write_all(br_sslio_context *cc, const void *src, size_t len);

/*
 * Make sure that any buffered application data in the provided context
 * get packed up and sent unto the low_write() callback method. If that
 * callback method represents a buffered system, it is up to the caller
 * to then "flush" that system too.
 *
 * Returned value is 0 on success, -1 on error.
 */
int br_sslio_flush(br_sslio_context *cc);

/*
 * Perform a SSL close. This implies sending a close_notify, and reading
 * the response from the server. Returned value is 0 on success, -1 on
 * error.
 */
int br_sslio_close(br_sslio_context *cc);

/* ===================================================================== */

/*
 * Symbolic constants for cipher suites.
 */

/* From RFC 5246 */
#define BR_TLS_NULL_WITH_NULL_NULL                   0x0000
#define BR_TLS_RSA_WITH_NULL_MD5                     0x0001
#define BR_TLS_RSA_WITH_NULL_SHA                     0x0002
#define BR_TLS_RSA_WITH_NULL_SHA256                  0x003B
#define BR_TLS_RSA_WITH_RC4_128_MD5                  0x0004
#define BR_TLS_RSA_WITH_RC4_128_SHA                  0x0005
#define BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA             0x000A
#define BR_TLS_RSA_WITH_AES_128_CBC_SHA              0x002F
#define BR_TLS_RSA_WITH_AES_256_CBC_SHA              0x0035
#define BR_TLS_RSA_WITH_AES_128_CBC_SHA256           0x003C
#define BR_TLS_RSA_WITH_AES_256_CBC_SHA256           0x003D
#define BR_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA          0x000D
#define BR_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA          0x0010
#define BR_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA         0x0013
#define BR_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA         0x0016
#define BR_TLS_DH_DSS_WITH_AES_128_CBC_SHA           0x0030
#define BR_TLS_DH_RSA_WITH_AES_128_CBC_SHA           0x0031
#define BR_TLS_DHE_DSS_WITH_AES_128_CBC_SHA          0x0032
#define BR_TLS_DHE_RSA_WITH_AES_128_CBC_SHA          0x0033
#define BR_TLS_DH_DSS_WITH_AES_256_CBC_SHA           0x0036
#define BR_TLS_DH_RSA_WITH_AES_256_CBC_SHA           0x0037
#define BR_TLS_DHE_DSS_WITH_AES_256_CBC_SHA          0x0038
#define BR_TLS_DHE_RSA_WITH_AES_256_CBC_SHA          0x0039
#define BR_TLS_DH_DSS_WITH_AES_128_CBC_SHA256        0x003E
#define BR_TLS_DH_RSA_WITH_AES_128_CBC_SHA256        0x003F
#define BR_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256       0x0040
#define BR_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       0x0067
#define BR_TLS_DH_DSS_WITH_AES_256_CBC_SHA256        0x0068
#define BR_TLS_DH_RSA_WITH_AES_256_CBC_SHA256        0x0069
#define BR_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256       0x006A
#define BR_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       0x006B
#define BR_TLS_DH_anon_WITH_RC4_128_MD5              0x0018
#define BR_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA         0x001B
#define BR_TLS_DH_anon_WITH_AES_128_CBC_SHA          0x0034
#define BR_TLS_DH_anon_WITH_AES_256_CBC_SHA          0x003A
#define BR_TLS_DH_anon_WITH_AES_128_CBC_SHA256       0x006C
#define BR_TLS_DH_anon_WITH_AES_256_CBC_SHA256       0x006D

/* From RFC 4492 */
#define BR_TLS_ECDH_ECDSA_WITH_NULL_SHA              0xC001
#define BR_TLS_ECDH_ECDSA_WITH_RC4_128_SHA           0xC002
#define BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA      0xC003
#define BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA       0xC004
#define BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA       0xC005
#define BR_TLS_ECDHE_ECDSA_WITH_NULL_SHA             0xC006
#define BR_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA          0xC007
#define BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA     0xC008
#define BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA      0xC009
#define BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA      0xC00A
#define BR_TLS_ECDH_RSA_WITH_NULL_SHA                0xC00B
#define BR_TLS_ECDH_RSA_WITH_RC4_128_SHA             0xC00C
#define BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA        0xC00D
#define BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA         0xC00E
#define BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA         0xC00F
#define BR_TLS_ECDHE_RSA_WITH_NULL_SHA               0xC010
#define BR_TLS_ECDHE_RSA_WITH_RC4_128_SHA            0xC011
#define BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA       0xC012
#define BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA        0xC013
#define BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA        0xC014
#define BR_TLS_ECDH_anon_WITH_NULL_SHA               0xC015
#define BR_TLS_ECDH_anon_WITH_RC4_128_SHA            0xC016
#define BR_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA       0xC017
#define BR_TLS_ECDH_anon_WITH_AES_128_CBC_SHA        0xC018
#define BR_TLS_ECDH_anon_WITH_AES_256_CBC_SHA        0xC019

/* From RFC 5288 */
#define BR_TLS_RSA_WITH_AES_128_GCM_SHA256           0x009C
#define BR_TLS_RSA_WITH_AES_256_GCM_SHA384           0x009D
#define BR_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       0x009E
#define BR_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       0x009F
#define BR_TLS_DH_RSA_WITH_AES_128_GCM_SHA256        0x00A0
#define BR_TLS_DH_RSA_WITH_AES_256_GCM_SHA384        0x00A1
#define BR_TLS_DHE_DSS_WITH_AES_128_GCM_SHA256       0x00A2
#define BR_TLS_DHE_DSS_WITH_AES_256_GCM_SHA384       0x00A3
#define BR_TLS_DH_DSS_WITH_AES_128_GCM_SHA256        0x00A4
#define BR_TLS_DH_DSS_WITH_AES_256_GCM_SHA384        0x00A5
#define BR_TLS_DH_anon_WITH_AES_128_GCM_SHA256       0x00A6
#define BR_TLS_DH_anon_WITH_AES_256_GCM_SHA384       0x00A7

/* From RFC 5289 */
#define BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256   0xC023
#define BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384   0xC024
#define BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256    0xC025
#define BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384    0xC026
#define BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256     0xC027
#define BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384     0xC028
#define BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256      0xC029
#define BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384      0xC02A
#define BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   0xC02B
#define BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   0xC02C
#define BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256    0xC02D
#define BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384    0xC02E
#define BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     0xC02F
#define BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     0xC030
#define BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256      0xC031
#define BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384      0xC032

/* From RFC 7905 */
#define BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCA8
#define BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA9
#define BR_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       0xCCAA
#define BR_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256           0xCCAB
#define BR_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256     0xCCAC
#define BR_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256       0xCCAD
#define BR_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256       0xCCAE

/*
 * Symbolic constants for alerts.
 */
#define BR_ALERT_CLOSE_NOTIFY                0
#define BR_ALERT_UNEXPECTED_MESSAGE         10
#define BR_ALERT_BAD_RECORD_MAC             20
#define BR_ALERT_RECORD_OVERFLOW            22
#define BR_ALERT_DECOMPRESSION_FAILURE      30
#define BR_ALERT_HANDSHAKE_FAILURE          40
#define BR_ALERT_BAD_CERTIFICATE            42
#define BR_ALERT_UNSUPPORTED_CERTIFICATE    43
#define BR_ALERT_CERTIFICATE_REVOKED        44
#define BR_ALERT_CERTIFICATE_EXPIRED        45
#define BR_ALERT_CERTIFICATE_UNKNOWN        46
#define BR_ALERT_ILLEGAL_PARAMETER          47
#define BR_ALERT_UNKNOWN_CA                 48
#define BR_ALERT_ACCESS_DENIED              49
#define BR_ALERT_DECODE_ERROR               50
#define BR_ALERT_DECRYPT_ERROR              51
#define BR_ALERT_PROTOCOL_VERSION           70
#define BR_ALERT_INSUFFICIENT_SECURITY      71
#define BR_ALERT_INTERNAL_ERROR             80
#define BR_ALERT_USER_CANCELED              90
#define BR_ALERT_NO_RENEGOTIATION          100
#define BR_ALERT_UNSUPPORTED_EXTENSION     110

#endif
