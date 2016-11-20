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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "brssl.h"
#include "bearssl.h"

static void
dump_blob(const char *name, const void *data, size_t len)
{
	const unsigned char *buf;
	size_t u;

	buf = data;
	fprintf(stderr, "%s (len = %lu)", name, (unsigned long)len);
	for (u = 0; u < len; u ++) {
		if ((u & 15) == 0) {
			fprintf(stderr, "\n%08lX  ", (unsigned long)u);
		} else if ((u & 7) == 0) {
			fprintf(stderr, " ");
		}
		fprintf(stderr, " %02x", buf[u]);
	}
	fprintf(stderr, "\n");
}

/*
 * Inspect the provided data in case it is a "command" to trigger a
 * special behaviour. If the command is recognised, then it is executed
 * and this function returns 1. Otherwise, this function returns 0.
 */
static int
run_command(br_ssl_engine_context *cc, unsigned char *buf, size_t len)
{
	/*
	 * A single static slot for saving session parameters.
	 */
	static br_ssl_session_parameters slot;
	static int slot_used = 0;

	size_t u;

	if (len < 2 || len > 3) {
		return 0;
	}
	if (len == 3 && (buf[1] != '\r' || buf[2] != '\n')) {
		return 0;
	}
	if (len == 2 && buf[1] != '\n') {
		return 0;
	}
	switch (buf[0]) {
	case 'Q':
		fprintf(stderr, "closing...\n");
		br_ssl_engine_close(cc);
		return 1;
	case 'R':
		if (br_ssl_engine_renegotiate(cc)) {
			fprintf(stderr, "renegotiating...\n");
		} else {
			fprintf(stderr, "not renegotiating.\n");
		}
		return 1;
	case 'F':
		/*
		 * Session forget is nominally client-only. But the
		 * session parameters are in the engine structure, which
		 * is the first field of the client context, so the cast
		 * still works properly. On the server, this forgetting
		 * has no effect.
		 */
		fprintf(stderr, "forgetting session...\n");
		br_ssl_client_forget_session((br_ssl_client_context *)cc);
		return 1;
	case 'S':
		fprintf(stderr, "saving session parameters...\n");
		br_ssl_engine_get_session_parameters(cc, &slot);
		fprintf(stderr, "  id = ");
		for (u = 0; u < slot.session_id_len; u ++) {
			fprintf(stderr, "%02X", slot.session_id[u]);
		}
		fprintf(stderr, "\n");
		slot_used = 1;
		return 1;
	case 'P':
		if (slot_used) {
			fprintf(stderr, "restoring session parameters...\n");
			fprintf(stderr, "  id = ");
			for (u = 0; u < slot.session_id_len; u ++) {
				fprintf(stderr, "%02X", slot.session_id[u]);
			}
			fprintf(stderr, "\n");
			br_ssl_engine_set_session_parameters(cc, &slot);
			return 1;
		}
		return 0;
	default:
		return 0;
	}
}

/* see brssl.h */
int
run_ssl_engine(br_ssl_engine_context *cc, int fd, unsigned flags)
{
	int hsdetails;
	int retcode;
	int verbose;
	int trace;

	hsdetails = 0;
	retcode = 0;
	verbose = (flags & RUN_ENGINE_VERBOSE) != 0;
	trace = (flags & RUN_ENGINE_TRACE) != 0;

	/*
	 * Make sure that stdin and stdout are non-blocking.
	 */
	fcntl(0, F_SETFL, O_NONBLOCK);
	fcntl(1, F_SETFL, O_NONBLOCK);

	/*
	 * Perform the loop.
	 */
	for (;;) {
		unsigned st;
		int sendrec, recvrec, sendapp, recvapp;
		struct pollfd pfd[3];
		int n;
		size_t u, k_fd, k_in, k_out;

		/*
		 * Get current engine state.
		 */
		st = br_ssl_engine_current_state(cc);
		if (st == BR_SSL_CLOSED) {
			int err;

			err = br_ssl_engine_last_error(cc);
			if (err == BR_ERR_OK) {
				if (verbose) {
					fprintf(stderr,
						"SSL closed normally\n");
				}
				retcode = 0;
				goto engine_exit;
			} else {
				fprintf(stderr, "ERROR: SSL error %d", err);
				retcode = err;
				if (err >= BR_ERR_SEND_FATAL_ALERT) {
					err -= BR_ERR_SEND_FATAL_ALERT;
					fprintf(stderr,
						" (sent alert %d)\n", err);
				} else if (err >= BR_ERR_RECV_FATAL_ALERT) {
					err -= BR_ERR_RECV_FATAL_ALERT;
					fprintf(stderr,
						" (received alert %d)\n", err);
				} else {
					const char *ename;

					ename = find_error_name(err, NULL);
					if (ename == NULL) {
						ename = "unknown";
					}
					fprintf(stderr, " (%s)\n", ename);
				}
				goto engine_exit;
			}
		}

		/*
		 * Compute descriptors that must be polled, depending
		 * on engine state.
		 */
		sendrec = ((st & BR_SSL_SENDREC) != 0);
		recvrec = ((st & BR_SSL_RECVREC) != 0);
		sendapp = ((st & BR_SSL_SENDAPP) != 0);
		recvapp = ((st & BR_SSL_RECVAPP) != 0);
		if (verbose && sendapp && !hsdetails) {
			char csn[80];

			fprintf(stderr, "Handshake completed\n");
			fprintf(stderr, "   version:               ");
			switch (cc->session.version) {
			case BR_SSL30:
				fprintf(stderr, "SSL 3.0");
				break;
			case BR_TLS10:
				fprintf(stderr, "TLS 1.0");
				break;
			case BR_TLS11:
				fprintf(stderr, "TLS 1.1");
				break;
			case BR_TLS12:
				fprintf(stderr, "TLS 1.2");
				break;
			default:
				fprintf(stderr, "unknown (0x%04X)",
					(unsigned)cc->session.version);
				break;
			}
			fprintf(stderr, "\n");
			get_suite_name_ext(
				cc->session.cipher_suite, csn, sizeof csn);
			fprintf(stderr, "   cipher suite:          %s\n", csn);
			fprintf(stderr, "   secure renegotiation:  %s\n",
				cc->reneg == 1 ? "no" : "yes");
			hsdetails = 1;
		}

		k_fd = 0;
		k_in = 0;
		k_out = 0;

		u = 0;
		if (sendrec || recvrec) {
			pfd[u].fd = fd;
			pfd[u].revents = 0;
			pfd[u].events = 0;
			if (sendrec) {
				pfd[u].events |= POLLOUT;
			}
			if (recvrec) {
				pfd[u].events |= POLLIN;
			}
			k_fd = u;
			u ++;
		}
		if (sendapp) {
			pfd[u].fd = 0;
			pfd[u].revents = 0;
			pfd[u].events = POLLIN;
			k_in = u;
			u ++;
		}
		if (recvapp) {
			pfd[u].fd = 1;
			pfd[u].revents = 0;
			pfd[u].events = POLLOUT;
			k_out = u;
			u ++;
		}
		n = poll(pfd, u, -1);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("ERROR: poll()");
			retcode = -2;
			goto engine_exit;
		}
		if (n == 0) {
			continue;
		}

		/*
		 * We transform closures/errors into read+write accesses
		 * so as to force the read() or write() call that will
		 * detect the situation.
		 */
		while (u -- > 0) {
			if (pfd[u].revents & (POLLERR | POLLHUP)) {
				pfd[u].revents |= POLLIN | POLLOUT;
			}
		}

		/*
		 * We give preference to outgoing data, on stdout and on
		 * the socket.
		 */
		if (recvapp) {
			if (pfd[k_out].revents & POLLOUT) {
				unsigned char *buf;
				size_t len;
				ssize_t wlen;

				buf = br_ssl_engine_recvapp_buf(cc, &len);
				wlen = write(1, buf, len);
				if (wlen <= 0) {
					if (verbose) {
						fprintf(stderr,
							"stdout closed...\n");
					}
					retcode = -2;
					goto engine_exit;
				}
				br_ssl_engine_recvapp_ack(cc, wlen);
				continue;
			}
		}
		if (sendrec) {
			if (pfd[k_fd].revents & POLLOUT) {
				unsigned char *buf;
				size_t len;
				ssize_t wlen;

				buf = br_ssl_engine_sendrec_buf(cc, &len);
				wlen = write(fd, buf, len);
				if (wlen <= 0) {
					if (verbose) {
						fprintf(stderr,
							"socket closed...\n");
					}
					retcode = -1;
					goto engine_exit;
				}
				if (trace) {
					dump_blob("Outgoing bytes", buf, wlen);
				}
				br_ssl_engine_sendrec_ack(cc, wlen);
				continue;
			}
		}
		if (recvrec) {
			if (pfd[k_fd].revents & POLLIN) {
				unsigned char *buf;
				size_t len;
				ssize_t rlen;

				buf = br_ssl_engine_recvrec_buf(cc, &len);
				rlen = read(fd, buf, len);
				if (rlen <= 0) {
					if (verbose) {
						fprintf(stderr,
							"socket closed...\n");
					}
					retcode = -1;
					goto engine_exit;
				}
				if (trace) {
					dump_blob("Incoming bytes", buf, rlen);
				}
				br_ssl_engine_recvrec_ack(cc, rlen);
				continue;
			}
		}
		if (sendapp) {
			if (pfd[k_in].revents & POLLIN) {
				unsigned char *buf;
				size_t len;
				ssize_t rlen;

				buf = br_ssl_engine_sendapp_buf(cc, &len);
				rlen = read(0, buf, len);
				if (rlen <= 0) {
					if (verbose) {
						fprintf(stderr,
							"stdin closed...\n");
					}
					br_ssl_engine_close(cc);
				} else if (!run_command(cc, buf, rlen)) {
					br_ssl_engine_sendapp_ack(cc, rlen);
				}
				br_ssl_engine_flush(cc, 0);
				continue;
			}
		}

		/* We should never reach that point. */
		fprintf(stderr, "ERROR: poll() misbehaves\n");
		retcode = -2;
		goto engine_exit;
	}

	/*
	 * Release allocated structures.
	 */
engine_exit:
	return retcode;
}
