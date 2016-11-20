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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "brssl.h"
#include "bearssl.h"

static int
host_connect(const char *host, const char *port, int verbose)
{
	struct addrinfo hints, *si, *p;
	int fd;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hints, &si);
	if (err != 0) {
		fprintf(stderr, "ERROR: getaddrinfo(): %s\n",
			gai_strerror(err));
		return -1;
	}
	fd = -1;
	for (p = si; p != NULL; p = p->ai_next) {
		if (verbose) {
			struct sockaddr *sa;
			void *addr;
			char tmp[INET6_ADDRSTRLEN + 50];

			sa = (struct sockaddr *)p->ai_addr;
			if (sa->sa_family == AF_INET) {
				addr = &((struct sockaddr_in *)sa)->sin_addr;
			} else if (sa->sa_family == AF_INET6) {
				addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
			} else {
				addr = NULL;
			}
			if (addr != NULL) {
				if (!inet_ntop(p->ai_family, addr,
					tmp, sizeof tmp))
				{
					strcpy(tmp, "<invalid>");
				}
			} else {
				sprintf(tmp, "<unknown family: %d>",
					(int)sa->sa_family);
			}
			fprintf(stderr, "connecting to: %s\n", tmp);
		}
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			if (verbose) {
				perror("socket()");
			}
			continue;
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
			if (verbose) {
				perror("connect()");
			}
			close(fd);
			continue;
		}
		break;
	}
	if (p == NULL) {
		freeaddrinfo(si);
		fprintf(stderr, "ERROR: failed to connect\n");
		return -1;
	}
	freeaddrinfo(si);
	if (verbose) {
		fprintf(stderr, "connected.\n");
	}

	/*
	 * We make the socket non-blocking, since we are going to use
	 * poll() to organise I/O.
	 */
	fcntl(fd, F_SETFL, O_NONBLOCK);
	return fd;
}

static void
usage_client(void)
{
	fprintf(stderr,
"usage: brssl client server[:port] [ options ]\n");
	fprintf(stderr,
"options:\n");
	fprintf(stderr,
"   -q              suppress verbose messages\n");
	fprintf(stderr,
"   -trace          activate extra debug messages (dump of all packets)\n");
	fprintf(stderr,
"   -sni name       use this specific name for SNI\n");
	fprintf(stderr,
"   -nosni          do not send any SNI\n");
	fprintf(stderr,
"   -mono           use monodirectional buffering\n");
	fprintf(stderr,
"   -buf length     set the I/O buffer length (in bytes)\n");
	fprintf(stderr,
"   -CA file        add certificates in 'file' to trust anchors\n");
	fprintf(stderr,
"   -list           list supported names (protocols, algorithms...)\n");
	fprintf(stderr,
"   -vmin name      set minimum supported version (default: TLS-1.0)\n");
	fprintf(stderr,
"   -vmax name      set maximum supported version (default: TLS-1.2)\n");
	fprintf(stderr,
"   -cs names       set list of supported cipher suites (comma-separated)\n");
	fprintf(stderr,
"   -hf names       add support for some hash functions (comma-separated)\n");
	fprintf(stderr,
"   -minhello len   set minimum ClientHello length (in bytes)\n");
	fprintf(stderr,
"   -fallback       send the TLS_FALLBACK_SCSV (i.e. claim a downgrade)\n");
}

/* see brssl.h */
int
do_client(int argc, char *argv[])
{
	int retcode;
	int verbose;
	int trace;
	int i, bidi;
	const char *server_name;
	char *host;
	char *port;
	const char *sni;
	anchor_list anchors = VEC_INIT;
	unsigned vmin, vmax;
	cipher_suite *suites;
	size_t num_suites;
	uint16_t *suite_ids;
	unsigned hfuns;
	size_t u;
	br_ssl_client_context cc;
	br_x509_minimal_context xc;
	x509_noanchor_context xwc;
	const br_hash_class *dnhash;
	unsigned char *iobuf;
	size_t iobuf_len;
	size_t minhello_len;
	int fallback;
	int fd;

	retcode = 0;
	verbose = 1;
	trace = 0;
	server_name = NULL;
	host = NULL;
	port = NULL;
	sni = NULL;
	bidi = 1;
	vmin = 0;
	vmax = 0;
	suites = NULL;
	num_suites = 0;
	hfuns = 0;
	suite_ids = NULL;
	iobuf = NULL;
	iobuf_len = 0;
	minhello_len = (size_t)-1;
	fallback = 0;
	fd = -1;
	for (i = 0; i < argc; i ++) {
		const char *arg;

		arg = argv[i];
		if (arg[0] != '-') {
			if (server_name != NULL) {
				fprintf(stderr,
					"ERROR: duplicate server name\n");
				usage_client();
				goto client_exit_error;
			}
			server_name = arg;
			continue;
		}
		if (eqstr(arg, "-v") || eqstr(arg, "-verbose")) {
			verbose = 1;
		} else if (eqstr(arg, "-q") || eqstr(arg, "-quiet")) {
			verbose = 0;
		} else if (eqstr(arg, "-trace")) {
			trace = 1;
		} else if (eqstr(arg, "-sni")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-sni'\n");
				usage_client();
				goto client_exit_error;
			}
			if (sni != NULL) {
				fprintf(stderr, "ERROR: duplicate SNI\n");
				usage_client();
				goto client_exit_error;
			}
			sni = argv[i];
		} else if (eqstr(arg, "-nosni")) {
			if (sni != NULL) {
				fprintf(stderr, "ERROR: duplicate SNI\n");
				usage_client();
				goto client_exit_error;
			}
			sni = "";
		} else if (eqstr(arg, "-mono")) {
			bidi = 0;
		} else if (eqstr(arg, "-buf")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-buf'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (iobuf_len != 0) {
				fprintf(stderr,
					"ERROR: duplicate I/O buffer length\n");
				usage_client();
				goto client_exit_error;
			}
			iobuf_len = parse_size(arg);
			if (iobuf_len == (size_t)-1) {
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-CA")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-CA'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (read_trust_anchors(&anchors, arg) == 0) {
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-list")) {
			list_names();
			goto client_exit;
		} else if (eqstr(arg, "-vmin")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-vmin'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (vmin != 0) {
				fprintf(stderr,
					"ERROR: duplicate minimum version\n");
				usage_client();
				goto client_exit_error;
			}
			vmin = parse_version(arg, strlen(arg));
			if (vmin == 0) {
				fprintf(stderr,
					"ERROR: unrecognised version '%s'\n",
					arg);
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-vmax")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-vmax'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (vmax != 0) {
				fprintf(stderr,
					"ERROR: duplicate maximum version\n");
				usage_client();
				goto client_exit_error;
			}
			vmax = parse_version(arg, strlen(arg));
			if (vmax == 0) {
				fprintf(stderr,
					"ERROR: unrecognised version '%s'\n",
					arg);
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-cs")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-cs'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (suites != NULL) {
				fprintf(stderr, "ERROR: duplicate list"
					" of cipher suites\n");
				usage_client();
				goto client_exit_error;
			}
			suites = parse_suites(arg, &num_suites);
			if (suites == NULL) {
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-hf")) {
			unsigned x;

			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-hf'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			x = parse_hash_functions(arg);
			if (x == 0) {
				usage_client();
				goto client_exit_error;
			}
			hfuns |= x;
		} else if (eqstr(arg, "-minhello")) {
			if (++ i >= argc) {
				fprintf(stderr,
					"ERROR: no argument for '-minhello'\n");
				usage_client();
				goto client_exit_error;
			}
			arg = argv[i];
			if (minhello_len != (size_t)-1) {
				fprintf(stderr, "ERROR: duplicate minium"
					" ClientHello length\n");
				usage_client();
				goto client_exit_error;
			}
			minhello_len = parse_size(arg);
			/*
			 * Minimum ClientHello length must fit on 16 bits.
			 */
			if (minhello_len == (size_t)-1
				|| (((minhello_len >> 12) >> 4) != 0))
			{
				usage_client();
				goto client_exit_error;
			}
		} else if (eqstr(arg, "-fallback")) {
			fallback = 1;
		} else {
			fprintf(stderr, "ERROR: unknown option: '%s'\n", arg);
			usage_client();
			goto client_exit_error;
		}
	}
	if (server_name == NULL) {
		fprintf(stderr, "ERROR: no server name/address provided\n");
		usage_client();
		goto client_exit_error;
	}
	for (u = strlen(server_name); u > 0; u --) {
		int c = server_name[u - 1];
		if (c == ':') {
			break;
		}
		if (c < '0' || c > '9') {
			u = 0;
			break;
		}
	}
	if (u == 0) {
		host = xstrdup(server_name);
		port = "443";
	} else {
		port = xstrdup(server_name + u);
		host = xmalloc(u);
		memcpy(host, server_name, u - 1);
		host[u - 1] = 0;
	}
	if (sni == NULL) {
		sni = host;
	}

	if (vmin == 0) {
		vmin = BR_TLS10;
	}
	if (vmax == 0) {
		vmax = BR_TLS12;
	}
	if (vmax < vmin) {
		fprintf(stderr, "ERROR: impossible minimum/maximum protocol"
			" version combination\n");
		usage_client();
		goto client_exit_error;
	}
	if (suites == NULL) {
		num_suites = 0;

		for (u = 0; cipher_suites[u].name; u ++) {
			if ((cipher_suites[u].req & REQ_TLS12) == 0
				|| vmax >= BR_TLS12)
			{
				num_suites ++;
			}
		}
		suites = xmalloc(num_suites * sizeof *suites);
		num_suites = 0;
		for (u = 0; cipher_suites[u].name; u ++) {
			if ((cipher_suites[u].req & REQ_TLS12) == 0
				|| vmax >= BR_TLS12)
			{
				suites[num_suites ++] = cipher_suites[u];
			}
		}
	}
	if (hfuns == 0) {
		hfuns = (unsigned)-1;
	}
	if (iobuf_len == 0) {
		if (bidi) {
			iobuf_len = BR_SSL_BUFSIZE_BIDI;
		} else {
			iobuf_len = BR_SSL_BUFSIZE_MONO;
		}
	}
	iobuf = xmalloc(iobuf_len);

	/*
	 * Compute implementation requirements and inject implementations.
	 */
	suite_ids = xmalloc((num_suites + 1) * sizeof *suite_ids);
	br_ssl_client_zero(&cc);
	br_ssl_engine_set_versions(&cc.eng, vmin, vmax);
	dnhash = NULL;
	for (u = 0; hash_functions[u].name; u ++) {
		const br_hash_class *hc;
		int id;

		hc = hash_functions[u].hclass;
		id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
		if ((hfuns & ((unsigned)1 << id)) != 0) {
			dnhash = hc;
		}
	}
	if (dnhash == NULL) {
		fprintf(stderr, "ERROR: no supported hash function\n");
		goto client_exit_error;
	}
	br_x509_minimal_init(&xc, dnhash,
		&VEC_ELT(anchors, 0), VEC_LEN(anchors));
	if (vmin <= BR_TLS11) {
		if (!(hfuns & (1 << br_md5_ID))) {
			fprintf(stderr, "ERROR: TLS 1.0 and 1.1 need MD5\n");
			goto client_exit_error;
		}
		if (!(hfuns & (1 << br_sha1_ID))) {
			fprintf(stderr, "ERROR: TLS 1.0 and 1.1 need SHA-1\n");
			goto client_exit_error;
		}
	}
	for (u = 0; u < num_suites; u ++) {
		unsigned req;

		req = suites[u].req;
		suite_ids[u] = suites[u].suite;
		if ((req & REQ_TLS12) != 0 && vmax < BR_TLS12) {
			fprintf(stderr,
				"ERROR: cipher suite %s requires TLS 1.2\n",
				suites[u].name);
			goto client_exit_error;
		}
		if ((req & REQ_SHA1) != 0 && !(hfuns & (1 << br_sha1_ID))) {
			fprintf(stderr,
				"ERROR: cipher suite %s requires SHA-1\n",
				suites[u].name);
			goto client_exit_error;
		}
		if ((req & REQ_SHA256) != 0 && !(hfuns & (1 << br_sha256_ID))) {
			fprintf(stderr,
				"ERROR: cipher suite %s requires SHA-256\n",
				suites[u].name);
			goto client_exit_error;
		}
		if ((req & REQ_SHA384) != 0 && !(hfuns & (1 << br_sha384_ID))) {
			fprintf(stderr,
				"ERROR: cipher suite %s requires SHA-384\n",
				suites[u].name);
			goto client_exit_error;
		}
		/* TODO: algorithm implementation selection */
		if ((req & REQ_AESCBC) != 0) {
			br_ssl_engine_set_aes_cbc(&cc.eng,
				&br_aes_ct_cbcenc_vtable,
				&br_aes_ct_cbcdec_vtable);
			br_ssl_engine_set_cbc(&cc.eng,
				&br_sslrec_in_cbc_vtable,
				&br_sslrec_out_cbc_vtable);
		}
		if ((req & REQ_AESGCM) != 0) {
			br_ssl_engine_set_aes_ctr(&cc.eng,
				&br_aes_ct_ctr_vtable);
			br_ssl_engine_set_ghash(&cc.eng,
				&br_ghash_ctmul);
			br_ssl_engine_set_gcm(&cc.eng,
				&br_sslrec_in_gcm_vtable,
				&br_sslrec_out_gcm_vtable);
		}
		if ((req & REQ_3DESCBC) != 0) {
			br_ssl_engine_set_des_cbc(&cc.eng,
				&br_des_ct_cbcenc_vtable,
				&br_des_ct_cbcdec_vtable);
			br_ssl_engine_set_cbc(&cc.eng,
				&br_sslrec_in_cbc_vtable,
				&br_sslrec_out_cbc_vtable);
		}
		if ((req & REQ_RSAKEYX) != 0) {
			br_ssl_client_set_rsapub(&cc, &br_rsa_i31_public);
		}
		if ((req & REQ_ECDHE_RSA) != 0) {
			br_ssl_engine_set_ec(&cc.eng, &br_ec_prime_i31);
			br_ssl_client_set_rsavrfy(&cc, &br_rsa_i31_pkcs1_vrfy);
		}
		if ((req & REQ_ECDHE_ECDSA) != 0) {
			br_ssl_engine_set_ec(&cc.eng, &br_ec_prime_i31);
			br_ssl_client_set_ecdsa(&cc, &br_ecdsa_i31_vrfy_asn1);
		}
		if ((req & REQ_ECDH) != 0) {
			br_ssl_engine_set_ec(&cc.eng, &br_ec_prime_i31);
		}
	}
	if (fallback) {
		suite_ids[num_suites ++] = 0x5600;
	}
	br_ssl_engine_set_suites(&cc.eng, suite_ids, num_suites);

	for (u = 0; hash_functions[u].name; u ++) {
		const br_hash_class *hc;
		int id;

		hc = hash_functions[u].hclass;
		id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
		if ((hfuns & ((unsigned)1 << id)) != 0) {
			br_ssl_engine_set_hash(&cc.eng, id, hc);
			br_x509_minimal_set_hash(&xc, id, hc);
		}
	}
	if (vmin <= BR_TLS11) {
		br_ssl_engine_set_prf10(&cc.eng, &br_tls10_prf);
	}
	if (vmax >= BR_TLS12) {
		if ((hfuns & ((unsigned)1 << br_sha256_ID)) != 0) {
			br_ssl_engine_set_prf_sha256(&cc.eng,
				&br_tls12_sha256_prf);
		}
		if ((hfuns & ((unsigned)1 << br_sha384_ID)) != 0) {
			br_ssl_engine_set_prf_sha384(&cc.eng,
				&br_tls12_sha384_prf);
		}
	}
	br_x509_minimal_set_rsa(&xc, &br_rsa_i31_pkcs1_vrfy);
	br_x509_minimal_set_ecdsa(&xc,
		&br_ec_prime_i31, &br_ecdsa_i31_vrfy_asn1);

	/*
	 * If there is no provided trust anchor, then certificate validation
	 * will always fail. In that situation, we use our custom wrapper
	 * that tolerates unknown anchors.
	 */
	if (VEC_LEN(anchors) == 0) {
		if (verbose) {
			fprintf(stderr,
				"WARNING: no configured trust anchor\n");
		}
		x509_noanchor_init(&xwc, &xc.vtable);
		br_ssl_engine_set_x509(&cc.eng, &xwc.vtable);
	} else {
		br_ssl_engine_set_x509(&cc.eng, &xc.vtable);
	}

	if (minhello_len != (size_t)-1) {
		br_ssl_client_set_min_clienthello_len(&cc, minhello_len);
	}

	br_ssl_engine_set_buffer(&cc.eng, iobuf, iobuf_len, bidi);
	br_ssl_client_reset(&cc, sni, 0);

	/*
	 * We need to avoid SIGPIPE.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Connect to the peer.
	 */
	fd = host_connect(host, port, verbose);
	if (fd < 0) {
		goto client_exit_error;
	}

	/*
	 * Run the engine until completion.
	 */
	if (run_ssl_engine(&cc.eng, fd,
		(verbose ? RUN_ENGINE_VERBOSE : 0)
		| (trace ? RUN_ENGINE_TRACE : 0)) != 0)
	{
		goto client_exit_error;
	} else {
		goto client_exit;
	}

	/*
	 * Release allocated structures.
	 */
client_exit:
	xfree(host);
	xfree(suites);
	xfree(suite_ids);
	VEC_CLEAREXT(anchors, &free_ta_contents);
	xfree(iobuf);
	if (fd >= 0) {
		close(fd);
	}
	return retcode;

client_exit_error:
	retcode = -1;
	goto client_exit;
}
