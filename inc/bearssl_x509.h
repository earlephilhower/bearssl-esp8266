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

#ifndef BR_BEARSSL_X509_H__
#define BR_BEARSSL_X509_H__

#include <stddef.h>
#include <stdint.h>

#include "bearssl_ec.h"
#include "bearssl_hash.h"
#include "bearssl_rsa.h"

/*
 * X.509 Certificate Chain Processing
 * ----------------------------------
 *
 * An X.509 processing engine receives an X.509 chain, chunk by chunk,
 * as received from a SSL/TLS client or server (the client receives the
 * server's certificate chain, and the server receives the client's
 * certificate chain if it requested a client certificate). The chain
 * is thus injected in the engine in SSL order (end-entity first).
 *
 * The engine's job is to return the public key to use for SSL/TLS.
 * How exactly that key is obtained and verified is entirely up to the
 * engine.
 */

/*
 * X.509 error codes are in the 32..63 range.
 */

/* Validation was successful; this is not actually an error. */
#define BR_ERR_X509_OK                    32

/* Invalid value in an ASN.1 structure. */
#define BR_ERR_X509_INVALID_VALUE         33

/* Truncated certificate. */
#define BR_ERR_X509_TRUNCATED             34

/* Empty certificate chain (no certificate at all). */
#define BR_ERR_X509_EMPTY_CHAIN           35

/* Decoding error: inner element extends beyond outer element size. */
#define BR_ERR_X509_INNER_TRUNC           36

/* Decoding error: unsupported tag class (application or private). */
#define BR_ERR_X509_BAD_TAG_CLASS         37

/* Decoding error: unsupported tag value. */
#define BR_ERR_X509_BAD_TAG_VALUE         38

/* Decoding error: indefinite length. */
#define BR_ERR_X509_INDEFINITE_LENGTH     39

/* Decoding error: extraneous element. */
#define BR_ERR_X509_EXTRA_ELEMENT         40

/* Decoding error: unexpected element. */
#define BR_ERR_X509_UNEXPECTED            41

/* Decoding error: expected constructed element, but is primitive. */
#define BR_ERR_X509_NOT_CONSTRUCTED       42

/* Decoding error: expected primitive element, but is constructed. */
#define BR_ERR_X509_NOT_PRIMITIVE         43

/* Decoding error: BIT STRING length is not multiple of 8. */
#define BR_ERR_X509_PARTIAL_BYTE          44

/* Decoding error: BOOLEAN value has invalid length. */
#define BR_ERR_X509_BAD_BOOLEAN           45

/* Decoding error: value is off-limits. */
#define BR_ERR_X509_OVERFLOW              46

/* Invalid distinguished name. */
#define BR_ERR_X509_BAD_DN                47

/* Invalid date/time representation. */
#define BR_ERR_X509_BAD_TIME              48

/* Certificate contains unsupported features that cannot be ignored. */
#define BR_ERR_X509_UNSUPPORTED           49

/* Key or signature size exceeds internal limits. */
#define BR_ERR_X509_LIMIT_EXCEEDED        50

/* Key type does not match that which was expected. */
#define BR_ERR_X509_WRONG_KEY_TYPE        51

/* Signature is invalid. */
#define BR_ERR_X509_BAD_SIGNATURE         52

/* Validation time is unknown. */
#define BR_ERR_X509_TIME_UNKNOWN          53

/* Certificate is expired or not yet valid. */
#define BR_ERR_X509_EXPIRED               54

/* Issuer/Subject DN mismatch in the chain. */
#define BR_ERR_X509_DN_MISMATCH           55

/* Expected server name was not found in the chain. */
#define BR_ERR_X509_BAD_SERVER_NAME       56

/* Unknown critical extension in certificate. */
#define BR_ERR_X509_CRITICAL_EXTENSION    57

/* Not a CA, or path length constraint violation */
#define BR_ERR_X509_NOT_CA                58

/* Key Usage extension prohibits intended usage. */
#define BR_ERR_X509_FORBIDDEN_KEY_USAGE   59

/* Public key found in certificate is too small. */
#define BR_ERR_X509_WEAK_PUBLIC_KEY       60

/* Chain could not be linked to a trust anchor. */
#define BR_ERR_X509_NOT_TRUSTED           62

/*
 * A structure to encode public keys.
 */
typedef struct {
	unsigned char key_type;
	union {
		br_rsa_public_key rsa;
		br_ec_public_key ec;
	} key;
} br_x509_pkey;

/*
 * A trust anchor consists in:
 * -- an encoded DN
 * -- a public key
 * -- flags
 */
typedef struct {
	unsigned char *dn;
	size_t dn_len;
	/* unsigned char hashed_DN[64]; */
	unsigned flags;
	br_x509_pkey pkey;
} br_x509_trust_anchor;

/* Trust anchor flag: trust anchor is a CA and thus acceptable for
   signing other certificates. Without this flag, the trust anchor
   is only for direct trust (name and key match EE certificate). */
#define BR_X509_TA_CA        0x0001

/*
 * Key type: combination of a basic key type (low 4 bits) and some
 * optional flags.
 *
 * For a public key, the basic key type only is set.
 *
 * For an expected key type, the flags indicate the intended purpose(s)
 * for the key; the basic key type may be set to 0 to indicate that any
 * key type compatible with the indicated purpose is acceptable.
 */
#define BR_KEYTYPE_RSA    1
#define BR_KEYTYPE_EC     2

#define BR_KEYTYPE_KEYX   0x10   /* key is for key exchange or encryption */
#define BR_KEYTYPE_SIGN   0x20   /* key is for verifying signatures */

/*
 * start_chain   Called when a new chain is started. If 'server_name'
 *               is not NULL and non-empty, then it is a name that
 *               should be looked for in the EE certificate (in the
 *               SAN extension as dNSName, or in the subjectDN's CN
 *               if there is no SAN extension).
 *               The caller ensures that the provided 'server_name'
 *               pointer remains valid throughout validation.
 *
 * start_cert    Begins a new certificate in the chain. The provided
 *               length is in bytes; this is the total certificate length.
 *
 * append        Get some additional bytes for the current certificate.
 *
 * end_cert      Ends the current certificate.
 *
 * end_chain     Called at the end of the chain. Returned value is
 *               0 on success, or a non-zero error code.
 *
 * get_pkey      Returns the EE certificate public key.
 *
 * For a complete chain, start_chain() and end_chain() are always
 * called. For each certificate, start_cert(), some append() calls, then
 * end_cert() are called, in that order. There may be no append() call
 * at all if the certificate is empty (which is not valid but may happen
 * if the peer sends exactly that).
 *
 * get_pkey() shall return a pointer to a structure that is valid as
 * long as a new chain is not started. This may be a sub-structure
 * within the context for the engine. This function MAY return a valid
 * pointer to a public key even in some cases of validation failure,
 * depending on the validation engine.
 */
typedef struct br_x509_class_ br_x509_class;
struct br_x509_class_ {
	size_t context_size;
	void (*start_chain)(const br_x509_class **ctx,
		unsigned expected_key_type,
		const char *server_name);
	void (*start_cert)(const br_x509_class **ctx, uint32_t length);
	void (*append)(const br_x509_class **ctx,
		const unsigned char *buf, size_t len);
	void (*end_cert)(const br_x509_class **ctx);
	unsigned (*end_chain)(const br_x509_class **ctx);
	const br_x509_pkey *(*get_pkey)(const br_x509_class *const *ctx);
};

/*
 * The "known key" X.509 engine is a trivial engine that completely
 * ignores the certificates, and instead reports an externally
 * configured public key.
 */
typedef struct {
	const br_x509_class *vtable;
	br_x509_pkey pkey;
} br_x509_knownkey_context;
extern const br_x509_class br_x509_knownkey_vtable;

/*
 * Initialize a "known key" X.509 engine with a known RSA public key.
 * The provided pointers are linked in, not copied, so they must
 * remain valid while the public key may be in usage (i.e. at least up
 * to the end of the handshake -- and since there may be renegotiations,
 * these buffers should stay until the connection is finished).
 */
void br_x509_knownkey_init_rsa(br_x509_knownkey_context *ctx,
	const br_rsa_public_key *pk);

/*
 * Initialize a "known key" X.509 engine with a known EC public key.
 * The provided pointers are linked in, not copied, so they must
 * remain valid while the public key may be in usage (i.e. at least up
 * to the end of the handshake -- and since there may be renegotiations,
 * these buffers should stay until the connection is finished).
 */
void br_x509_knownkey_init_ec(br_x509_knownkey_context *ctx,
	const br_ec_public_key *pk);

/*
 * The minimal X.509 engine has some state buffers which must be large
 * enough to simultaneously accommodate:
 * -- the public key extracted from the current certificate;
 * -- the signature on the current certificate or on the previous
 *    certificate;
 * -- the public key extracted from the EE certificate.
 *
 * We store public key elements in their raw unsigned big-endian
 * encoding. We want to support up to RSA-4096 with a short (up to 64
 * bits) public exponent, thus a buffer for a public key must have
 * length at least 520 bytes. Similarly, a RSA-4096 signature has length
 * 512 bytes.
 *
 * Though RSA public exponents can formally be as large as the modulus
 * (mathematically, even larger exponents would work, but PKCS#1 forbids
 * them), exponents that do not fit on 32 bits are extremely rare,
 * notably because some widespread implementation (e.g. Microsoft's
 * CryptoAPI) don't support them. Moreover, large public exponent do not
 * seem to imply any tangible security benefit, and they increase the
 * cost of public key operations.
 *
 * EC public keys are shorter than RSA public keys; even with curve
 * NIST P-521 (the largest curve we care to support), a public key is
 * encoded over 133 bytes only.
 */
#define BR_X509_BUFSIZE_KEY   520
#define BR_X509_BUFSIZE_SIG   512

/*
 * The "minimal" X.509 engine performs basic decoding of certificates and
 * some validations:
 *  -- DN matching
 *  -- signatures
 *  -- validity dates
 *  -- Basic Constraints extension
 *  -- Server name check against SAN extension
 */
typedef struct {
	const br_x509_class *vtable;

	/* Structure for returning the EE public key. */
	br_x509_pkey pkey;

	/* CPU for the T0 virtual machine. */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	int err;

	/* Server name to match with the SAN / CN of the EE certificate. */
	const char *server_name;

	/* Expected EE key type and usage. */
	unsigned char expected_key_type;

	/* Explicitly set date and time. */
	uint32_t days, seconds;

	/* Current certificate length (in bytes). Set to 0 when the
	   certificate has been fully processed. */
	uint32_t cert_length;

	/* Number of certificates processed so far in the current chain.
	   It is incremented at the end of the processing of a certificate,
	   so it is 0 for the EE. */
	uint32_t num_certs;

	/* Certificate data chunk. */
	const unsigned char *hbuf;
	size_t hlen;

	/* The pad serves as destination for various operations. */
	unsigned char pad[256];

	/* Buffer for EE public key data. */
	unsigned char ee_pkey_data[BR_X509_BUFSIZE_KEY];

	/* Buffer for currently decoded public key. */
	unsigned char pkey_data[BR_X509_BUFSIZE_KEY];

	/* Signature type: signer key type, offset to the hash
	   function OID (in the T0 data block) and hash function
	   output length (TBS hash length). */
	unsigned char cert_signer_key_type;
	uint16_t cert_sig_hash_oid;
	unsigned char cert_sig_hash_len;

	/* Current/last certificate signature. */
	unsigned char cert_sig[BR_X509_BUFSIZE_SIG];
	uint16_t cert_sig_len;

	/* Minimum RSA key length (difference in bytes from 128). */
	int16_t min_rsa_size;

	/* Configured trust anchors. */
	const br_x509_trust_anchor *trust_anchors;
	size_t trust_anchors_num;

	/*
	 * Multi-hasher for the TBS.
	 */
	unsigned char do_mhash;
	br_multihash_context mhash;
	unsigned char tbs_hash[64];

	/*
	 * Simple hasher for the subject/issuer DN.
	 */
	unsigned char do_dn_hash;
	const br_hash_class *dn_hash_impl;
	br_hash_compat_context dn_hash;
	unsigned char current_dn_hash[64];
	unsigned char next_dn_hash[64];
	unsigned char saved_dn_hash[64];

	/*
	 * Public key cryptography implementations (signature verification).
	 */
	br_rsa_pkcs1_vrfy irsa;
	br_ecdsa_vrfy iecdsa;
	const br_ec_impl *iec;

} br_x509_minimal_context;
extern const br_x509_class br_x509_minimal_vtable;

/*
 * Initialize a "minimal" X.509 engine. Parameters are:
 *  -- context to initialize
 *  -- hash function to use for hashing normalized DN
 *  -- list of trust anchors
 *
 * After initialization, some hash function implementations for signature
 * verification MUST be added.
 */
void br_x509_minimal_init(br_x509_minimal_context *ctx,
	const br_hash_class *dn_hash_impl,
	const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num);

/*
 * Set a hash function implementation, identified by ID, for purposes of
 * verifying signatures on certificates. This must be called after
 * br_x509_minimal_init().
 */
static inline void
br_x509_minimal_set_hash(br_x509_minimal_context *ctx,
	int id, const br_hash_class *impl)
{
	br_multihash_setimpl(&ctx->mhash, id, impl);
}

/*
 * Set a RSA implementation, for purposes of verifying signatures on
 * certificates. This must be called after br_x509_minimal_init().
 */
static inline void
br_x509_minimal_set_rsa(br_x509_minimal_context *ctx,
	br_rsa_pkcs1_vrfy irsa)
{
	ctx->irsa = irsa;
}

/*
 * Set an ECDSA implementation, for purposes of verifying signatures on
 * certificates. This must be called after br_x509_minimal_init().
 */
static inline void
br_x509_minimal_set_ecdsa(br_x509_minimal_context *ctx,
	const br_ec_impl *iec, br_ecdsa_vrfy iecdsa)
{
	ctx->iecdsa = iecdsa;
	ctx->iec = iec;
}

/*
 * Set the validation time, normally to the current date and time.
 * This consists in two 32-bit counts:
 *
 * -- Days are counted in a proleptic Gregorian calendar since
 * January 1st, 0 AD. Year "0 AD" is the one that preceded "1 AD";
 * it is also traditionally known as "1 BC".
 *
 * -- Seconds are counted since midnight, from 0 to 86400 (a count of
 * 86400 is possible only if a leap second happened).
 *
 * If the validation date and time are not explicitly set, but BearSSL
 * was compiled with support for the system clock on the underlying
 * platform, then the current time will automatically be used. Otherwise,
 * validation will fail (except in case of direct trust of the EE key).
 */
static inline void
br_x509_minimal_set_time(br_x509_minimal_context *ctx,
	uint32_t days, uint32_t seconds)
{
	ctx->days = days;
	ctx->seconds = seconds;
}

/*
 * Set the minimal acceptable length for RSA keys, in bytes. Default
 * is 128 bytes, which means RSA keys of 1017 bits or more. This setting
 * applies to keys extracted from certificates (EE and intermediate CA).
 * It does _not_ apply to "CA" trust anchors.
 */
static inline void
br_x509_minimal_set_minrsa(br_x509_minimal_context *ctx, int byte_length)
{
	ctx->min_rsa_size = (int16_t)(byte_length - 128);
}

/*
 * An X.509 decoder context. This is not for X.509 validation, but for
 * using certificates as trust anchors (e.g. self-signed certificates
 * read from files).
 */
typedef struct {

	/* Structure for returning the public key. */
	br_x509_pkey pkey;

	/* CPU for the T0 virtual machine. */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	int err;

	/* The pad serves as destination for various operations. */
	unsigned char pad[256];

	/* Flag set when decoding succeeds. */
	unsigned char decoded;

	/* Validity dates. */
	uint32_t notbefore_days, notbefore_seconds;
	uint32_t notafter_days, notafter_seconds;

	/* The "CA" flag. This is set to true if the certificate contains
	   a Basic Constraints extension that asserts CA status. */
	unsigned char isCA;

	/* DN processing: the subject DN is extracted and pushed to the
	   provided callback. */
	unsigned char copy_dn;
	void *append_dn_ctx;
	void (*append_dn)(void *ctx, const void *buf, size_t len);

	/* Certificate data chunk. */
	const unsigned char *hbuf;
	size_t hlen;

	/* Buffer for decoded public key. */
	unsigned char pkey_data[BR_X509_BUFSIZE_KEY];

	/* Type of key and hash function used in the certificate signature. */
	unsigned char signer_key_type;
	unsigned char signer_hash_id;

} br_x509_decoder_context;

/*
 * Initialise an X.509 decoder context for processing a new certificate.
 */
void br_x509_decoder_init(br_x509_decoder_context *ctx,
	void (*append_dn)(void *ctx, const void *buf, size_t len),
	void *append_dn_ctx);

/*
 * Push some certificate bytes into a decoder context.
 */
void br_x509_decoder_push(br_x509_decoder_context *ctx,
	const void *data, size_t len);

/*
 * Obtain the decoded public key. Returned value is a pointer to a
 * structure internal to the decoder context; releasing or reusing the
 * decoder context invalidates that structure.
 *
 * If decoding was not finished, or failed, then NULL is returned.
 */
static inline br_x509_pkey *
br_x509_decoder_get_pkey(br_x509_decoder_context *ctx)
{
	if (ctx->decoded && ctx->err == 0) {
		return &ctx->pkey;
	} else {
		return NULL;
	}
}

/*
 * Get decoder error. If no error was reported yet but the certificate
 * decoding is not finished, then the error code is BR_ERR_X509_TRUNCATED.
 * If decoding was successful, then 0 is returned.
 */
static inline int
br_x509_decoder_last_error(br_x509_decoder_context *ctx)
{
	if (ctx->err != 0) {
		return ctx->err;
	}
	if (!ctx->decoded) {
		return BR_ERR_X509_TRUNCATED;
	}
	return 0;
}

/*
 * Get the "isCA" flag from an X.509 decoder context. This flag is set
 * if the decoded certificate claims to be a CA through a Basic
 * Constraints extension.
 */
static inline int
br_x509_decoder_isCA(br_x509_decoder_context *ctx)
{
	return ctx->isCA;
}

/*
 * Get the issuing CA key type (type of key used to sign the decoded
 * certificate). This is BR_KEYTYPE_RSA or BR_KEYTYPE_EC. The value 0
 * is returned if the signature type was not recognised.
 */
static inline int
br_x509_decoder_get_signer_key_type(br_x509_decoder_context *ctx)
{
	return ctx->signer_key_type;
}

/*
 * Get the identifier for the hash function used to sign the decoded
 * certificate. This is 0 if the hash function was not recognised.
 */
static inline int
br_x509_decoder_get_signer_hash_id(br_x509_decoder_context *ctx)
{
	return ctx->signer_hash_id;
}

/*
 * Type for an X.509 certificate (DER-encoded).
 */
typedef struct {
	unsigned char *data;
	size_t data_len;
} br_x509_certificate;

/*
 * Private key decoder context.
 */
typedef struct {

	/* Structure for returning the private key. */
	union {
		br_rsa_private_key rsa;
		br_ec_private_key ec;
	} key;

	/* CPU for the T0 virtual machine. */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	int err;

	/* Private key data chunk. */
	const unsigned char *hbuf;
	size_t hlen;

	/* The pad serves as destination for various operations. */
	unsigned char pad[256];

	/* Decoded key type; 0 until decoding is complete. */
	unsigned char key_type;

	/* Buffer for the private key elements. It shall be large enough
	   to accommodate all elements for a RSA-4096 private key (roughly
	   five 2048-bit integers, possibly a bit more). */
	unsigned char key_data[3 * BR_X509_BUFSIZE_SIG];

} br_skey_decoder_context;

/*
 * Initialise a private key decoder context.
 */
void br_skey_decoder_init(br_skey_decoder_context *ctx);

/*
 * Push some data bytes into a private key decoder context.
 */
void br_skey_decoder_push(br_skey_decoder_context *ctx,
	const void *data, size_t len);

/*
 * Get the decoding status for a private key. This is either 0 on success,
 * or a non-zero error code.
 */
static inline int
br_skey_decoder_last_error(const br_skey_decoder_context *ctx)
{
	if (ctx->err != 0) {
		return ctx->err;
	}
	if (ctx->key_type == 0) {
		return BR_ERR_X509_TRUNCATED;
	}
	return 0;
}

/*
 * Get the decoded private key type. This is 0 if decoding is not finished
 * or failed.
 */
static inline int
br_skey_decoder_key_type(const br_skey_decoder_context *ctx)
{
	if (ctx->err == 0) {
		return ctx->key_type;
	} else {
		return 0;
	}
}

/*
 * Get the decoded RSA private key. This function returns NULL if the
 * decoding failed, or is not finished, or the key is not RSA. The returned
 * pointer references structures within the context that can become
 * invalid if the context is reused or released.
 */
static inline const br_rsa_private_key *
br_skey_decoder_get_rsa(const br_skey_decoder_context *ctx)
{
	if (ctx->err == 0 && ctx->key_type == BR_KEYTYPE_RSA) {
		return &ctx->key.rsa;
	} else {
		return NULL;
	}
}

/*
 * Get the decoded EC private key. This function returns NULL if the
 * decoding failed, or is not finished, or the key is not EC. The returned
 * pointer references structures within the context that can become
 * invalid if the context is reused or released.
 */
static inline const br_ec_private_key *
br_skey_decoder_get_ec(const br_skey_decoder_context *ctx)
{
	if (ctx->err == 0 && ctx->key_type == BR_KEYTYPE_EC) {
		return &ctx->key.ec;
	} else {
		return NULL;
	}
}

#endif
