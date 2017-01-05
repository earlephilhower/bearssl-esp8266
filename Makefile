# Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
#
# Permission is hereby granted, free of charge, to any person obtaining 
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be 
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

.POSIX:

# ========================================================================
# Configurable elements: C compiler and flags, linker flags, static
# library archival command.

CC = gcc
CFLAGS = -W -Wall -Os -fPIC -I src -I inc
#CFLAGS = -W -Wall -g -fPIC -I src -I inc
LDFLAGS = 
AR = ar -rcs

# Nothing is meant to be changed below this line.

# ========================================================================

HEADERS = inc/bearssl.h inc/bearssl_block.h inc/bearssl_ec.h inc/bearssl_hash.h inc/bearssl_hmac.h inc/bearssl_pem.h inc/bearssl_prf.h inc/bearssl_rand.h inc/bearssl_rsa.h inc/bearssl_ssl.h inc/bearssl_x509.h src/inner.h src/config.h
BUILD = build

BEARSSLLIB = libbearssl.a
BRSSL = brssl
TESTCRYPTO = testcrypto
TESTSPEED = testspeed
TESTX509 = testx509
TESTMATH = testmath

OBJCODEC = $(BUILD)/ccopy.o $(BUILD)/dec16be.o $(BUILD)/dec16le.o $(BUILD)/dec32be.o $(BUILD)/dec32le.o $(BUILD)/dec64be.o $(BUILD)/dec64le.o $(BUILD)/enc16be.o $(BUILD)/enc16le.o $(BUILD)/enc32be.o $(BUILD)/enc32le.o $(BUILD)/enc64be.o $(BUILD)/enc64le.o $(BUILD)/pemdec.o
OBJEC = $(BUILD)/ec_p256_i15.o $(BUILD)/ec_prime_i15.o $(BUILD)/ec_prime_i31.o $(BUILD)/ec_secp256r1.o $(BUILD)/ec_secp384r1.o $(BUILD)/ec_secp521r1.o $(BUILD)/ecdsa_atr.o $(BUILD)/ecdsa_i15_bits.o $(BUILD)/ecdsa_i15_sign_asn1.o $(BUILD)/ecdsa_i15_sign_raw.o $(BUILD)/ecdsa_i15_vrfy_asn1.o $(BUILD)/ecdsa_i15_vrfy_raw.o $(BUILD)/ecdsa_i31_bits.o $(BUILD)/ecdsa_i31_sign_asn1.o $(BUILD)/ecdsa_i31_sign_raw.o $(BUILD)/ecdsa_i31_vrfy_asn1.o $(BUILD)/ecdsa_i31_vrfy_raw.o $(BUILD)/ecdsa_rta.o
# $(BUILD)/ec_prime_i31_secp256r1.o $(BUILD)/ec_prime_i31_secp384r1.o $(BUILD)/ec_prime_i31_secp521r1.o
OBJHASH = $(BUILD)/dig_oid.o $(BUILD)/dig_size.o $(BUILD)/ghash_ctmul.o $(BUILD)/ghash_ctmul32.o $(BUILD)/ghash_ctmul64.o $(BUILD)/md5.o $(BUILD)/md5sha1.o $(BUILD)/multihash.o $(BUILD)/sha1.o $(BUILD)/sha2big.o $(BUILD)/sha2small.o
OBJINT15 = $(BUILD)/i15_core.o $(BUILD)/i15_ext1.o $(BUILD)/i15_ext2.o
OBJINT31 = $(BUILD)/i31_add.o $(BUILD)/i31_bitlen.o $(BUILD)/i31_decmod.o $(BUILD)/i31_decode.o $(BUILD)/i31_decred.o $(BUILD)/i31_encode.o $(BUILD)/i31_fmont.o $(BUILD)/i31_iszero.o $(BUILD)/i31_modpow.o $(BUILD)/i31_montmul.o $(BUILD)/i31_mulacc.o $(BUILD)/i31_muladd.o $(BUILD)/i31_ninv31.o $(BUILD)/i31_reduce.o $(BUILD)/i31_rshift.o $(BUILD)/i31_sub.o $(BUILD)/i31_tmont.o
OBJINT32 = $(BUILD)/i32_add.o $(BUILD)/i32_bitlen.o $(BUILD)/i32_decmod.o $(BUILD)/i32_decode.o $(BUILD)/i32_decred.o $(BUILD)/i32_div32.o $(BUILD)/i32_encode.o $(BUILD)/i32_fmont.o $(BUILD)/i32_iszero.o $(BUILD)/i32_modpow.o $(BUILD)/i32_montmul.o $(BUILD)/i32_mulacc.o $(BUILD)/i32_muladd.o $(BUILD)/i32_ninv32.o $(BUILD)/i32_reduce.o $(BUILD)/i32_sub.o $(BUILD)/i32_tmont.o
OBJMAC = $(BUILD)/hmac.o $(BUILD)/hmac_ct.o
OBJRAND = $(BUILD)/hmac_drbg.o
OBJRSA = $(BUILD)/rsa_i15_pkcs1_sign.o $(BUILD)/rsa_i15_pkcs1_vrfy.o $(BUILD)/rsa_i15_priv.o $(BUILD)/rsa_i15_pub.o $(BUILD)/rsa_i31_pkcs1_sign.o $(BUILD)/rsa_i31_pkcs1_vrfy.o $(BUILD)/rsa_i31_priv.o $(BUILD)/rsa_i31_pub.o $(BUILD)/rsa_i32_pkcs1_sign.o $(BUILD)/rsa_i32_pkcs1_vrfy.o $(BUILD)/rsa_i32_priv.o $(BUILD)/rsa_i32_pub.o $(BUILD)/rsa_pkcs1_sig_pad.o $(BUILD)/rsa_pkcs1_sig_unpad.o $(BUILD)/rsa_ssl_decrypt.o
OBJSSL = $(BUILD)/prf.o $(BUILD)/prf_md5sha1.o $(BUILD)/prf_sha256.o $(BUILD)/prf_sha384.o $(BUILD)/ssl_ccert_single_ec.o $(BUILD)/ssl_ccert_single_rsa.o $(BUILD)/ssl_client.o $(BUILD)/ssl_client_full.o $(BUILD)/ssl_engine.o $(BUILD)/ssl_hashes.o $(BUILD)/ssl_hs_client.o $(BUILD)/ssl_hs_server.o $(BUILD)/ssl_io.o $(BUILD)/ssl_lru.o $(BUILD)/ssl_rec_cbc.o $(BUILD)/ssl_rec_chapol.o $(BUILD)/ssl_rec_gcm.o $(BUILD)/ssl_server.o $(BUILD)/ssl_server_mine2c.o $(BUILD)/ssl_server_mine2g.o $(BUILD)/ssl_server_minf2c.o $(BUILD)/ssl_server_minf2g.o $(BUILD)/ssl_server_minr2g.o $(BUILD)/ssl_server_minu2g.o $(BUILD)/ssl_server_minv2g.o $(BUILD)/ssl_server_full_ec.o $(BUILD)/ssl_server_full_rsa.o $(BUILD)/ssl_scert_single_ec.o $(BUILD)/ssl_scert_single_rsa.o
OBJSYMCIPHER = $(BUILD)/aes_big_cbcdec.o $(BUILD)/aes_big_cbcenc.o $(BUILD)/aes_big_ctr.o $(BUILD)/aes_big_dec.o $(BUILD)/aes_big_enc.o $(BUILD)/aes_common.o $(BUILD)/aes_ct.o $(BUILD)/aes_ct64.o $(BUILD)/aes_ct64_cbcdec.o $(BUILD)/aes_ct64_cbcenc.o $(BUILD)/aes_ct64_ctr.o $(BUILD)/aes_ct64_dec.o $(BUILD)/aes_ct64_enc.o $(BUILD)/aes_ct_cbcdec.o $(BUILD)/aes_ct_cbcenc.o $(BUILD)/aes_ct_ctr.o $(BUILD)/aes_ct_dec.o $(BUILD)/aes_ct_enc.o $(BUILD)/aes_small_cbcdec.o $(BUILD)/aes_small_cbcenc.o $(BUILD)/aes_small_ctr.o $(BUILD)/aes_small_dec.o $(BUILD)/aes_small_enc.o $(BUILD)/chacha20_ct.o $(BUILD)/des_ct.o $(BUILD)/des_ct_cbcdec.o $(BUILD)/des_ct_cbcenc.o $(BUILD)/des_support.o $(BUILD)/des_tab.o $(BUILD)/des_tab_cbcdec.o $(BUILD)/des_tab_cbcenc.o $(BUILD)/poly1305_ctmul.o $(BUILD)/poly1305_ctmul32.o $(BUILD)/poly1305_i15.o
OBJX509 = $(BUILD)/skey_decoder.o $(BUILD)/x509_decoder.o $(BUILD)/x509_knownkey.o $(BUILD)/x509_minimal.o $(BUILD)/x509_minimal_full.o
OBJ = $(OBJCODEC) $(OBJEC) $(OBJHASH) $(OBJINT15) $(OBJINT31) $(OBJINT32) $(OBJMAC) $(OBJRAND) $(OBJRSA) $(OBJSSL) $(OBJSYMCIPHER) $(OBJX509)
OBJBRSSL = $(BUILD)/brssl.o $(BUILD)/certs.o $(BUILD)/chain.o $(BUILD)/client.o $(BUILD)/errors.o $(BUILD)/files.o $(BUILD)/keys.o $(BUILD)/names.o $(BUILD)/server.o $(BUILD)/skey.o $(BUILD)/sslio.o $(BUILD)/ta.o $(BUILD)/vector.o $(BUILD)/verify.o $(BUILD)/xmem.o
OBJTESTCRYPTO = $(BUILD)/test_crypto.o
OBJTESTSPEED = $(BUILD)/test_speed.o
OBJTESTX509 = $(BUILD)/test_x509.o
OBJTESTMATH = $(BUILD)/test_math.o

T0COMP = T0Comp.exe
T0SRC = T0/BlobWriter.cs T0/CPU.cs T0/CodeElement.cs T0/CodeElementJump.cs T0/CodeElementUInt.cs T0/CodeElementUIntExpr.cs T0/CodeElementUIntInt.cs T0/CodeElementUIntUInt.cs T0/ConstData.cs T0/Opcode.cs T0/OpcodeCall.cs T0/OpcodeConst.cs T0/OpcodeGetLocal.cs T0/OpcodeJump.cs T0/OpcodeJumpIf.cs T0/OpcodeJumpIfNot.cs T0/OpcodeJumpUncond.cs T0/OpcodePutLocal.cs T0/OpcodeRet.cs T0/SType.cs T0/T0Comp.cs T0/TPointerBase.cs T0/TPointerBlob.cs T0/TPointerExpr.cs T0/TPointerNull.cs T0/TPointerXT.cs T0/TValue.cs T0/Word.cs T0/WordBuilder.cs T0/WordData.cs T0/WordInterpreted.cs T0/WordNative.cs
T0KERN = T0/kern.t0

all: compile

compile: $(BEARSSLLIB) $(BRSSL) $(TESTCRYPTO) $(TESTSPEED) $(TESTX509)

$(BEARSSLLIB): $(BUILD) $(OBJ)
	$(AR) $(BEARSSLLIB) $(OBJ)

$(BRSSL): $(BEARSSLLIB) $(OBJBRSSL)
	$(CC) $(LDFLAGS) -o $(BRSSL) $(OBJBRSSL) $(BEARSSLLIB)

$(TESTCRYPTO): $(BEARSSLLIB) $(OBJTESTCRYPTO)
	$(CC) $(LDFLAGS) -o $(TESTCRYPTO) $(OBJTESTCRYPTO) $(BEARSSLLIB)

$(TESTSPEED): $(BEARSSLLIB) $(OBJTESTSPEED)
	$(CC) $(LDFLAGS) -o $(TESTSPEED) $(OBJTESTSPEED) $(BEARSSLLIB)

$(TESTX509): $(BEARSSLLIB) $(OBJTESTX509)
	$(CC) $(LDFLAGS) -o $(TESTX509) $(OBJTESTX509) $(BEARSSLLIB)

$(TESTMATH): $(BEARSSLLIB) $(OBJTESTMATH)
	$(CC) $(LDFLAGS) -o $(TESTMATH) $(OBJTESTMATH) $(BEARSSLLIB) -lgmp

$(BUILD):
	-mkdir -p $(BUILD)

T0: $(T0COMP) T0Gen

T0Gen:
	mono T0Comp.exe -o src/codec/pemdec -r br_pem_decoder src/codec/pemdec.t0
	mono T0Comp.exe -o src/ssl/ssl_hs_client -r br_ssl_hs_client src/ssl/ssl_hs_common.t0 src/ssl/ssl_hs_client.t0
	mono T0Comp.exe -o src/ssl/ssl_hs_server -r br_ssl_hs_server src/ssl/ssl_hs_common.t0 src/ssl/ssl_hs_server.t0
	mono T0Comp.exe -o src/x509/skey_decoder -r br_skey_decoder src/x509/asn1.t0 src/x509/skey_decoder.t0
	mono T0Comp.exe -o src/x509/x509_decoder -r br_x509_decoder src/x509/asn1.t0 src/x509/x509_decoder.t0
	mono T0Comp.exe -o src/x509/x509_minimal -r br_x509_minimal src/x509/asn1.t0 src/x509/x509_minimal.t0

$(T0COMP): $(T0SRC) $(T0KERN)
	./mkT0.sh

clean:
	-rm -f $(OBJ) $(BEARSSLLIB) $(OBJSSL) $(BRSSL) $(OBJBRSSL) $(TESTCRYPTO) $(OBJTESTCRYPTO) $(TESTSPEED) $(OBJTESTSPEED) $(TESTX509) $(OBJTESTX509) $(TESTMATH) $(OBJTESTMATH)

$(BUILD)/ccopy.o: src/codec/ccopy.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ccopy.o src/codec/ccopy.c

$(BUILD)/dec16be.o: src/codec/dec16be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec16be.o src/codec/dec16be.c

$(BUILD)/dec16le.o: src/codec/dec16le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec16le.o src/codec/dec16le.c

$(BUILD)/dec32be.o: src/codec/dec32be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec32be.o src/codec/dec32be.c

$(BUILD)/dec32le.o: src/codec/dec32le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec32le.o src/codec/dec32le.c

$(BUILD)/dec64be.o: src/codec/dec64be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec64be.o src/codec/dec64be.c

$(BUILD)/dec64le.o: src/codec/dec64le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dec64le.o src/codec/dec64le.c

$(BUILD)/enc16be.o: src/codec/enc16be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc16be.o src/codec/enc16be.c

$(BUILD)/enc16le.o: src/codec/enc16le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc16le.o src/codec/enc16le.c

$(BUILD)/enc32be.o: src/codec/enc32be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc32be.o src/codec/enc32be.c

$(BUILD)/enc32le.o: src/codec/enc32le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc32le.o src/codec/enc32le.c

$(BUILD)/enc64be.o: src/codec/enc64be.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc64be.o src/codec/enc64be.c

$(BUILD)/enc64le.o: src/codec/enc64le.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/enc64le.o src/codec/enc64le.c

$(BUILD)/pemdec.o: src/codec/pemdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/pemdec.o src/codec/pemdec.c

$(BUILD)/ec_g_secp256r1.o: src/ec/ec_g_secp256r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_g_secp256r1.o src/ec/ec_g_secp256r1.c

$(BUILD)/ec_g_secp384r1.o: src/ec/ec_g_secp384r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_g_secp384r1.o src/ec/ec_g_secp384r1.c

$(BUILD)/ec_g_secp521r1.o: src/ec/ec_g_secp521r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_g_secp521r1.o src/ec/ec_g_secp521r1.c

$(BUILD)/ec_p256_i15.o: src/ec/ec_p256_i15.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_p256_i15.o src/ec/ec_p256_i15.c

$(BUILD)/ec_prime_i15.o: src/ec/ec_prime_i15.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_prime_i15.o src/ec/ec_prime_i15.c

$(BUILD)/ec_prime_i31.o: src/ec/ec_prime_i31.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_prime_i31.o src/ec/ec_prime_i31.c

$(BUILD)/ec_prime_i31_secp256r1.o: src/ec/ec_prime_i31_secp256r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_prime_i31_secp256r1.o src/ec/ec_prime_i31_secp256r1.c

$(BUILD)/ec_prime_i31_secp384r1.o: src/ec/ec_prime_i31_secp384r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_prime_i31_secp384r1.o src/ec/ec_prime_i31_secp384r1.c

$(BUILD)/ec_prime_i31_secp521r1.o: src/ec/ec_prime_i31_secp521r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_prime_i31_secp521r1.o src/ec/ec_prime_i31_secp521r1.c

$(BUILD)/ec_secp256r1.o: src/ec/ec_secp256r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_secp256r1.o src/ec/ec_secp256r1.c

$(BUILD)/ec_secp384r1.o: src/ec/ec_secp384r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_secp384r1.o src/ec/ec_secp384r1.c

$(BUILD)/ec_secp521r1.o: src/ec/ec_secp521r1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ec_secp521r1.o src/ec/ec_secp521r1.c

$(BUILD)/ecdsa_atr.o: src/ec/ecdsa_atr.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_atr.o src/ec/ecdsa_atr.c

$(BUILD)/ecdsa_i15_bits.o: src/ec/ecdsa_i15_bits.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i15_bits.o src/ec/ecdsa_i15_bits.c

$(BUILD)/ecdsa_i15_sign_asn1.o: src/ec/ecdsa_i15_sign_asn1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i15_sign_asn1.o src/ec/ecdsa_i15_sign_asn1.c

$(BUILD)/ecdsa_i15_sign_raw.o: src/ec/ecdsa_i15_sign_raw.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i15_sign_raw.o src/ec/ecdsa_i15_sign_raw.c

$(BUILD)/ecdsa_i15_vrfy_asn1.o: src/ec/ecdsa_i15_vrfy_asn1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i15_vrfy_asn1.o src/ec/ecdsa_i15_vrfy_asn1.c

$(BUILD)/ecdsa_i15_vrfy_raw.o: src/ec/ecdsa_i15_vrfy_raw.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i15_vrfy_raw.o src/ec/ecdsa_i15_vrfy_raw.c

$(BUILD)/ecdsa_i31_bits.o: src/ec/ecdsa_i31_bits.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i31_bits.o src/ec/ecdsa_i31_bits.c

$(BUILD)/ecdsa_i31_sign_asn1.o: src/ec/ecdsa_i31_sign_asn1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i31_sign_asn1.o src/ec/ecdsa_i31_sign_asn1.c

$(BUILD)/ecdsa_i31_sign_raw.o: src/ec/ecdsa_i31_sign_raw.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i31_sign_raw.o src/ec/ecdsa_i31_sign_raw.c

$(BUILD)/ecdsa_i31_vrfy_asn1.o: src/ec/ecdsa_i31_vrfy_asn1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i31_vrfy_asn1.o src/ec/ecdsa_i31_vrfy_asn1.c

$(BUILD)/ecdsa_i31_vrfy_raw.o: src/ec/ecdsa_i31_vrfy_raw.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_i31_vrfy_raw.o src/ec/ecdsa_i31_vrfy_raw.c

$(BUILD)/ecdsa_rta.o: src/ec/ecdsa_rta.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ecdsa_rta.o src/ec/ecdsa_rta.c

$(BUILD)/dig_oid.o: src/hash/dig_oid.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dig_oid.o src/hash/dig_oid.c

$(BUILD)/dig_size.o: src/hash/dig_size.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/dig_size.o src/hash/dig_size.c

$(BUILD)/ghash_ctmul.o: src/hash/ghash_ctmul.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ghash_ctmul.o src/hash/ghash_ctmul.c

$(BUILD)/ghash_ctmul32.o: src/hash/ghash_ctmul32.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ghash_ctmul32.o src/hash/ghash_ctmul32.c

$(BUILD)/ghash_ctmul64.o: src/hash/ghash_ctmul64.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ghash_ctmul64.o src/hash/ghash_ctmul64.c

$(BUILD)/md5.o: src/hash/md5.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/md5.o src/hash/md5.c

$(BUILD)/md5sha1.o: src/hash/md5sha1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/md5sha1.o src/hash/md5sha1.c

$(BUILD)/multihash.o: src/hash/multihash.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/multihash.o src/hash/multihash.c

$(BUILD)/sha1.o: src/hash/sha1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/sha1.o src/hash/sha1.c

$(BUILD)/sha2big.o: src/hash/sha2big.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/sha2big.o src/hash/sha2big.c

$(BUILD)/sha2small.o: src/hash/sha2small.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/sha2small.o src/hash/sha2small.c

$(BUILD)/i15_core.o: src/int/i15_core.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i15_core.o src/int/i15_core.c

$(BUILD)/i15_ext1.o: src/int/i15_ext1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i15_ext1.o src/int/i15_ext1.c

$(BUILD)/i15_ext2.o: src/int/i15_ext2.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i15_ext2.o src/int/i15_ext2.c

$(BUILD)/i31_add.o: src/int/i31_add.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_add.o src/int/i31_add.c

$(BUILD)/i31_bitlen.o: src/int/i31_bitlen.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_bitlen.o src/int/i31_bitlen.c

$(BUILD)/i31_decmod.o: src/int/i31_decmod.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_decmod.o src/int/i31_decmod.c

$(BUILD)/i31_decode.o: src/int/i31_decode.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_decode.o src/int/i31_decode.c

$(BUILD)/i31_decred.o: src/int/i31_decred.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_decred.o src/int/i31_decred.c

$(BUILD)/i31_encode.o: src/int/i31_encode.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_encode.o src/int/i31_encode.c

$(BUILD)/i31_fmont.o: src/int/i31_fmont.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_fmont.o src/int/i31_fmont.c

$(BUILD)/i31_iszero.o: src/int/i31_iszero.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_iszero.o src/int/i31_iszero.c

$(BUILD)/i31_modpow.o: src/int/i31_modpow.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_modpow.o src/int/i31_modpow.c

$(BUILD)/i31_montmul.o: src/int/i31_montmul.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_montmul.o src/int/i31_montmul.c

$(BUILD)/i31_mulacc.o: src/int/i31_mulacc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_mulacc.o src/int/i31_mulacc.c

$(BUILD)/i31_muladd.o: src/int/i31_muladd.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_muladd.o src/int/i31_muladd.c

$(BUILD)/i31_ninv31.o: src/int/i31_ninv31.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_ninv31.o src/int/i31_ninv31.c

$(BUILD)/i31_reduce.o: src/int/i31_reduce.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_reduce.o src/int/i31_reduce.c

$(BUILD)/i31_rshift.o: src/int/i31_rshift.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_rshift.o src/int/i31_rshift.c

$(BUILD)/i31_sub.o: src/int/i31_sub.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_sub.o src/int/i31_sub.c

$(BUILD)/i31_tmont.o: src/int/i31_tmont.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i31_tmont.o src/int/i31_tmont.c

$(BUILD)/i32_add.o: src/int/i32_add.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_add.o src/int/i32_add.c

$(BUILD)/i32_bitlen.o: src/int/i32_bitlen.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_bitlen.o src/int/i32_bitlen.c

$(BUILD)/i32_decmod.o: src/int/i32_decmod.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_decmod.o src/int/i32_decmod.c

$(BUILD)/i32_decode.o: src/int/i32_decode.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_decode.o src/int/i32_decode.c

$(BUILD)/i32_decred.o: src/int/i32_decred.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_decred.o src/int/i32_decred.c

$(BUILD)/i32_div32.o: src/int/i32_div32.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_div32.o src/int/i32_div32.c

$(BUILD)/i32_encode.o: src/int/i32_encode.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_encode.o src/int/i32_encode.c

$(BUILD)/i32_fmont.o: src/int/i32_fmont.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_fmont.o src/int/i32_fmont.c

$(BUILD)/i32_iszero.o: src/int/i32_iszero.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_iszero.o src/int/i32_iszero.c

$(BUILD)/i32_modpow.o: src/int/i32_modpow.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_modpow.o src/int/i32_modpow.c

$(BUILD)/i32_montmul.o: src/int/i32_montmul.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_montmul.o src/int/i32_montmul.c

$(BUILD)/i32_mulacc.o: src/int/i32_mulacc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_mulacc.o src/int/i32_mulacc.c

$(BUILD)/i32_muladd.o: src/int/i32_muladd.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_muladd.o src/int/i32_muladd.c

$(BUILD)/i32_ninv32.o: src/int/i32_ninv32.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_ninv32.o src/int/i32_ninv32.c

$(BUILD)/i32_reduce.o: src/int/i32_reduce.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_reduce.o src/int/i32_reduce.c

$(BUILD)/i32_sub.o: src/int/i32_sub.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_sub.o src/int/i32_sub.c

$(BUILD)/i32_tmont.o: src/int/i32_tmont.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/i32_tmont.o src/int/i32_tmont.c

$(BUILD)/hmac.o: src/mac/hmac.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/hmac.o src/mac/hmac.c

$(BUILD)/hmac_ct.o: src/mac/hmac_ct.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/hmac_ct.o src/mac/hmac_ct.c

$(BUILD)/hmac_drbg.o: src/rand/hmac_drbg.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/hmac_drbg.o src/rand/hmac_drbg.c

$(BUILD)/rsa_i15_pkcs1_sign.o: src/rsa/rsa_i15_pkcs1_sign.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i15_pkcs1_sign.o src/rsa/rsa_i15_pkcs1_sign.c

$(BUILD)/rsa_i15_pkcs1_vrfy.o: src/rsa/rsa_i15_pkcs1_vrfy.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i15_pkcs1_vrfy.o src/rsa/rsa_i15_pkcs1_vrfy.c

$(BUILD)/rsa_i15_priv.o: src/rsa/rsa_i15_priv.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i15_priv.o src/rsa/rsa_i15_priv.c

$(BUILD)/rsa_i15_pub.o: src/rsa/rsa_i15_pub.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i15_pub.o src/rsa/rsa_i15_pub.c

$(BUILD)/rsa_i31_pkcs1_sign.o: src/rsa/rsa_i31_pkcs1_sign.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i31_pkcs1_sign.o src/rsa/rsa_i31_pkcs1_sign.c

$(BUILD)/rsa_i31_pkcs1_vrfy.o: src/rsa/rsa_i31_pkcs1_vrfy.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i31_pkcs1_vrfy.o src/rsa/rsa_i31_pkcs1_vrfy.c

$(BUILD)/rsa_i31_priv.o: src/rsa/rsa_i31_priv.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i31_priv.o src/rsa/rsa_i31_priv.c

$(BUILD)/rsa_i31_pub.o: src/rsa/rsa_i31_pub.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i31_pub.o src/rsa/rsa_i31_pub.c

$(BUILD)/rsa_i32_pkcs1_sign.o: src/rsa/rsa_i32_pkcs1_sign.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i32_pkcs1_sign.o src/rsa/rsa_i32_pkcs1_sign.c

$(BUILD)/rsa_i32_pkcs1_vrfy.o: src/rsa/rsa_i32_pkcs1_vrfy.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i32_pkcs1_vrfy.o src/rsa/rsa_i32_pkcs1_vrfy.c

$(BUILD)/rsa_i32_priv.o: src/rsa/rsa_i32_priv.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i32_priv.o src/rsa/rsa_i32_priv.c

$(BUILD)/rsa_i32_pub.o: src/rsa/rsa_i32_pub.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_i32_pub.o src/rsa/rsa_i32_pub.c

$(BUILD)/rsa_pkcs1_sig_pad.o: src/rsa/rsa_pkcs1_sig_pad.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_pkcs1_sig_pad.o src/rsa/rsa_pkcs1_sig_pad.c

$(BUILD)/rsa_pkcs1_sig_unpad.o: src/rsa/rsa_pkcs1_sig_unpad.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_pkcs1_sig_unpad.o src/rsa/rsa_pkcs1_sig_unpad.c

$(BUILD)/rsa_ssl_decrypt.o: src/rsa/rsa_ssl_decrypt.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/rsa_ssl_decrypt.o src/rsa/rsa_ssl_decrypt.c

$(BUILD)/prf.o: src/ssl/prf.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/prf.o src/ssl/prf.c

$(BUILD)/prf_md5sha1.o: src/ssl/prf_md5sha1.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/prf_md5sha1.o src/ssl/prf_md5sha1.c

$(BUILD)/prf_sha256.o: src/ssl/prf_sha256.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/prf_sha256.o src/ssl/prf_sha256.c

$(BUILD)/prf_sha384.o: src/ssl/prf_sha384.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/prf_sha384.o src/ssl/prf_sha384.c

$(BUILD)/ssl_ccert_single_ec.o: src/ssl/ssl_ccert_single_ec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_ccert_single_ec.o src/ssl/ssl_ccert_single_ec.c

$(BUILD)/ssl_ccert_single_rsa.o: src/ssl/ssl_ccert_single_rsa.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_ccert_single_rsa.o src/ssl/ssl_ccert_single_rsa.c

$(BUILD)/ssl_client.o: src/ssl/ssl_client.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_client.o src/ssl/ssl_client.c

$(BUILD)/ssl_client_full.o: src/ssl/ssl_client_full.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_client_full.o src/ssl/ssl_client_full.c

$(BUILD)/ssl_engine.o: src/ssl/ssl_engine.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_engine.o src/ssl/ssl_engine.c

$(BUILD)/ssl_hashes.o: src/ssl/ssl_hashes.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_hashes.o src/ssl/ssl_hashes.c

$(BUILD)/ssl_hs_client.o: src/ssl/ssl_hs_client.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_hs_client.o src/ssl/ssl_hs_client.c

$(BUILD)/ssl_hs_server.o: src/ssl/ssl_hs_server.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_hs_server.o src/ssl/ssl_hs_server.c

$(BUILD)/ssl_io.o: src/ssl/ssl_io.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_io.o src/ssl/ssl_io.c

$(BUILD)/ssl_lru.o: src/ssl/ssl_lru.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_lru.o src/ssl/ssl_lru.c

$(BUILD)/ssl_rec_cbc.o: src/ssl/ssl_rec_cbc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_rec_cbc.o src/ssl/ssl_rec_cbc.c

$(BUILD)/ssl_rec_chapol.o: src/ssl/ssl_rec_chapol.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_rec_chapol.o src/ssl/ssl_rec_chapol.c

$(BUILD)/ssl_rec_gcm.o: src/ssl/ssl_rec_gcm.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_rec_gcm.o src/ssl/ssl_rec_gcm.c

$(BUILD)/ssl_server.o: src/ssl/ssl_server.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server.o src/ssl/ssl_server.c

$(BUILD)/ssl_server_mine2c.o: src/ssl/ssl_server_mine2c.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_mine2c.o src/ssl/ssl_server_mine2c.c

$(BUILD)/ssl_server_mine2g.o: src/ssl/ssl_server_mine2g.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_mine2g.o src/ssl/ssl_server_mine2g.c

$(BUILD)/ssl_server_minf2c.o: src/ssl/ssl_server_minf2c.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_minf2c.o src/ssl/ssl_server_minf2c.c

$(BUILD)/ssl_server_minf2g.o: src/ssl/ssl_server_minf2g.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_minf2g.o src/ssl/ssl_server_minf2g.c

$(BUILD)/ssl_server_minr2g.o: src/ssl/ssl_server_minr2g.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_minr2g.o src/ssl/ssl_server_minr2g.c

$(BUILD)/ssl_server_minu2g.o: src/ssl/ssl_server_minu2g.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_minu2g.o src/ssl/ssl_server_minu2g.c

$(BUILD)/ssl_server_minv2g.o: src/ssl/ssl_server_minv2g.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_minv2g.o src/ssl/ssl_server_minv2g.c

$(BUILD)/ssl_server_full_ec.o: src/ssl/ssl_server_full_ec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_full_ec.o src/ssl/ssl_server_full_ec.c

$(BUILD)/ssl_server_full_rsa.o: src/ssl/ssl_server_full_rsa.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_server_full_rsa.o src/ssl/ssl_server_full_rsa.c

$(BUILD)/ssl_scert_single_ec.o: src/ssl/ssl_scert_single_ec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_scert_single_ec.o src/ssl/ssl_scert_single_ec.c

$(BUILD)/ssl_scert_single_rsa.o: src/ssl/ssl_scert_single_rsa.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ssl_scert_single_rsa.o src/ssl/ssl_scert_single_rsa.c

$(BUILD)/aes_big_cbcdec.o: src/symcipher/aes_big_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_big_cbcdec.o src/symcipher/aes_big_cbcdec.c

$(BUILD)/aes_big_cbcenc.o: src/symcipher/aes_big_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_big_cbcenc.o src/symcipher/aes_big_cbcenc.c

$(BUILD)/aes_big_ctr.o: src/symcipher/aes_big_ctr.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_big_ctr.o src/symcipher/aes_big_ctr.c

$(BUILD)/aes_big_dec.o: src/symcipher/aes_big_dec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_big_dec.o src/symcipher/aes_big_dec.c

$(BUILD)/aes_big_enc.o: src/symcipher/aes_big_enc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_big_enc.o src/symcipher/aes_big_enc.c

$(BUILD)/aes_common.o: src/symcipher/aes_common.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_common.o src/symcipher/aes_common.c

$(BUILD)/aes_ct.o: src/symcipher/aes_ct.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct.o src/symcipher/aes_ct.c

$(BUILD)/aes_ct64.o: src/symcipher/aes_ct64.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64.o src/symcipher/aes_ct64.c

$(BUILD)/aes_ct64_cbcdec.o: src/symcipher/aes_ct64_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64_cbcdec.o src/symcipher/aes_ct64_cbcdec.c

$(BUILD)/aes_ct64_cbcenc.o: src/symcipher/aes_ct64_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64_cbcenc.o src/symcipher/aes_ct64_cbcenc.c

$(BUILD)/aes_ct64_ctr.o: src/symcipher/aes_ct64_ctr.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64_ctr.o src/symcipher/aes_ct64_ctr.c

$(BUILD)/aes_ct64_dec.o: src/symcipher/aes_ct64_dec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64_dec.o src/symcipher/aes_ct64_dec.c

$(BUILD)/aes_ct64_enc.o: src/symcipher/aes_ct64_enc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct64_enc.o src/symcipher/aes_ct64_enc.c

$(BUILD)/aes_ct_cbcdec.o: src/symcipher/aes_ct_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct_cbcdec.o src/symcipher/aes_ct_cbcdec.c

$(BUILD)/aes_ct_cbcenc.o: src/symcipher/aes_ct_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct_cbcenc.o src/symcipher/aes_ct_cbcenc.c

$(BUILD)/aes_ct_ctr.o: src/symcipher/aes_ct_ctr.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct_ctr.o src/symcipher/aes_ct_ctr.c

$(BUILD)/aes_ct_dec.o: src/symcipher/aes_ct_dec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct_dec.o src/symcipher/aes_ct_dec.c

$(BUILD)/aes_ct_enc.o: src/symcipher/aes_ct_enc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_ct_enc.o src/symcipher/aes_ct_enc.c

$(BUILD)/aes_small_cbcdec.o: src/symcipher/aes_small_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_small_cbcdec.o src/symcipher/aes_small_cbcdec.c

$(BUILD)/aes_small_cbcenc.o: src/symcipher/aes_small_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_small_cbcenc.o src/symcipher/aes_small_cbcenc.c

$(BUILD)/aes_small_ctr.o: src/symcipher/aes_small_ctr.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_small_ctr.o src/symcipher/aes_small_ctr.c

$(BUILD)/aes_small_dec.o: src/symcipher/aes_small_dec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_small_dec.o src/symcipher/aes_small_dec.c

$(BUILD)/aes_small_enc.o: src/symcipher/aes_small_enc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/aes_small_enc.o src/symcipher/aes_small_enc.c

$(BUILD)/chacha20_ct.o: src/symcipher/chacha20_ct.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/chacha20_ct.o src/symcipher/chacha20_ct.c

$(BUILD)/des_ct.o: src/symcipher/des_ct.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_ct.o src/symcipher/des_ct.c

$(BUILD)/des_ct_cbcdec.o: src/symcipher/des_ct_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_ct_cbcdec.o src/symcipher/des_ct_cbcdec.c

$(BUILD)/des_ct_cbcenc.o: src/symcipher/des_ct_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_ct_cbcenc.o src/symcipher/des_ct_cbcenc.c

$(BUILD)/des_support.o: src/symcipher/des_support.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_support.o src/symcipher/des_support.c

$(BUILD)/des_tab.o: src/symcipher/des_tab.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_tab.o src/symcipher/des_tab.c

$(BUILD)/des_tab_cbcdec.o: src/symcipher/des_tab_cbcdec.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_tab_cbcdec.o src/symcipher/des_tab_cbcdec.c

$(BUILD)/des_tab_cbcenc.o: src/symcipher/des_tab_cbcenc.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/des_tab_cbcenc.o src/symcipher/des_tab_cbcenc.c

$(BUILD)/poly1305_ctmul.o: src/symcipher/poly1305_ctmul.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/poly1305_ctmul.o src/symcipher/poly1305_ctmul.c

$(BUILD)/poly1305_ctmul32.o: src/symcipher/poly1305_ctmul32.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/poly1305_ctmul32.o src/symcipher/poly1305_ctmul32.c

$(BUILD)/poly1305_i15.o: src/symcipher/poly1305_i15.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/poly1305_i15.o src/symcipher/poly1305_i15.c

$(BUILD)/skey_decoder.o: src/x509/skey_decoder.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/skey_decoder.o src/x509/skey_decoder.c

$(BUILD)/x509_decoder.o: src/x509/x509_decoder.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/x509_decoder.o src/x509/x509_decoder.c

$(BUILD)/x509_knownkey.o: src/x509/x509_knownkey.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/x509_knownkey.o src/x509/x509_knownkey.c

$(BUILD)/x509_minimal.o: src/x509/x509_minimal.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/x509_minimal.o src/x509/x509_minimal.c

$(BUILD)/x509_minimal_full.o: src/x509/x509_minimal_full.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/x509_minimal_full.o src/x509/x509_minimal_full.c

$(BUILD)/test_crypto.o: test/test_crypto.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/test_crypto.o test/test_crypto.c

$(BUILD)/test_math.o: test/test_math.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/test_math.o test/test_math.c

$(BUILD)/test_speed.o: test/test_speed.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/test_speed.o test/test_speed.c

$(BUILD)/test_x509.o: test/test_x509.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/test_x509.o test/test_x509.c

$(BUILD)/brssl.o: tools/brssl.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/brssl.o tools/brssl.c

$(BUILD)/certs.o: tools/certs.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/certs.o tools/certs.c

$(BUILD)/chain.o: tools/chain.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/chain.o tools/chain.c

$(BUILD)/client.o: tools/client.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/client.o tools/client.c

$(BUILD)/errors.o: tools/errors.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/errors.o tools/errors.c

$(BUILD)/files.o: tools/files.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/files.o tools/files.c

$(BUILD)/keys.o: tools/keys.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/keys.o tools/keys.c

$(BUILD)/names.o: tools/names.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/names.o tools/names.c

$(BUILD)/server.o: tools/server.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/server.o tools/server.c

$(BUILD)/skey.o: tools/skey.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/skey.o tools/skey.c

$(BUILD)/sslio.o: tools/sslio.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/sslio.o tools/sslio.c

$(BUILD)/ta.o: tools/ta.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/ta.o tools/ta.c

$(BUILD)/vector.o: tools/vector.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/vector.o tools/vector.c

$(BUILD)/verify.o: tools/verify.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/verify.o tools/verify.c

$(BUILD)/xmem.o: tools/xmem.c tools/brssl.h $(HEADERS)
	$(CC) $(CFLAGS) -c -o $(BUILD)/xmem.o tools/xmem.c
