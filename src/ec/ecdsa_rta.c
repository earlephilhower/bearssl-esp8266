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

static size_t
asn1_int_length(const unsigned char *x, size_t xlen)
{
	while (xlen > 0 && *x == 0) {
		x ++;
		xlen --;
	}
	if (xlen == 0 || *x >= 0x80) {
		xlen ++;
	}
	return xlen;
}

/* see bearssl_ec.h */
size_t
br_ecdsa_raw_to_asn1(void *sig, size_t sig_len)
{
	/*
	 * Internal buffer is large enough to accommodate a signature
	 * such that r and s fit on 125 bytes each (signed encoding),
	 * meaning a curve order of up to 1000 bits. This is the limit
	 * that ensures "simple" length encodings.
	 */
	unsigned char *buf;
	size_t hlen, rlen, slen, zlen, off;
	unsigned char tmp[257];

	buf = sig;
	if ((sig_len & 1) != 0) {
		return 0;
	}
	hlen = sig_len >> 1;
	rlen = asn1_int_length(buf, hlen);
	slen = asn1_int_length(buf + hlen, hlen);
	if (rlen > 125 || slen > 125) {
		return 0;
	}
	tmp[0] = 0x30;
	zlen = rlen + slen + 4;
	if (zlen >= 0x80) {
		tmp[1] = 0x81;
		tmp[2] = zlen;
		off = 3;
	} else {
		tmp[1] = zlen;
		off = 2;
	}
	tmp[off ++] = 0x02;
	tmp[off ++] = rlen;
	if (rlen > hlen) {
		tmp[off] = 0x00;
		memcpy(tmp + off + 1, buf, hlen);
	} else {
		memcpy(tmp + off, buf + hlen - rlen, rlen);
	}
	off += rlen;
	tmp[off ++] = 0x02;
	tmp[off ++] = slen;
	if (slen > hlen) {
		tmp[off] = 0x00;
		memcpy(tmp + off + 1, buf + hlen, hlen);
	} else {
		memcpy(tmp + off, buf + sig_len - slen, slen);
	}
	off += slen;
	memcpy(sig, tmp, off);
	return off;
}
