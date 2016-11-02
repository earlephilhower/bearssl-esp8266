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

#ifndef BR_BEARSSL_PEM_H__
#define BR_BEARSSL_PEM_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Context for a PEM decoder.
 */
typedef struct {
	/* CPU for the T0 virtual machine. */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	int err;

	const unsigned char *hbuf;
	size_t hlen;

	void (*dest)(void *dest_ctx, const void *src, size_t len);
	void *dest_ctx;

	unsigned char event;
	char name[128];
	unsigned char buf[255];
	size_t ptr;

} br_pem_decoder_context;

/*
 * Initialise a PEM decoder structure.
 */
void br_pem_decoder_init(br_pem_decoder_context *ctx);

/*
 * Push some bytes into the decoder. Returned value is the number of
 * bytes actually consumed; this may be less than the number of provided
 * bytes if an event is produced. When an event is produced, it must
 * be read (with br_pem_decoder_event()); until the event is read, this
 * function will return 0.
 */
size_t br_pem_decoder_push(br_pem_decoder_context *ctx,
	const void *data, size_t len);

/*
 * Set the receiver for decoded data. The provided function (with opaque
 * context pointer) will be called with successive data chunks.
 */
static inline void
br_pem_decoder_setdest(br_pem_decoder_context *ctx,
	void (*dest)(void *dest_ctx, const void *src, size_t len),
	void *dest_ctx)
{
	ctx->dest = dest;
	ctx->dest_ctx = dest_ctx;
}

/*
 * Get the last event. This is 0 if no event has been produced. Calling
 * ths function clears the event and allows new source bytes to be
 * processed.
 */
int br_pem_decoder_event(br_pem_decoder_context *ctx);

/*
 * This event is called when the start of a new object has been detected.
 * The object name (normalised to uppercase) can be accessed with
 * br_pem_decoder_name(). The caller MUST provide an appropriate receiver
 * (with br_pem_decoder_setdest()) before sending new data bytes.
 */
#define BR_PEM_BEGIN_OBJ   1

/*
 * This event is called when the end of the current object is reached
 * (normally).
 */
#define BR_PEM_END_OBJ     2

/*
 * This event is called when decoding fails while decoding an object.
 * This formally closes the current object and brings the decoder back
 * to the "out of any object" state. The offending line in the source
 * is consumed.
 */
#define BR_PEM_ERROR       3

/*
 * Get the name of the encountered object. That name is normalised to
 * uppercase (for ASCII characters).
 */
static inline const char *
br_pem_decoder_name(br_pem_decoder_context *ctx)
{
	return ctx->name;
}

#endif
