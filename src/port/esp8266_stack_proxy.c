#ifdef ESP8266
/*
 * Implement a stupid-simple stack variable replacement allocator
 * There are *massive* restrictions on its use, this is not a real malloc()!
 * There is no reentrancy, calls allocate/deallocate in strict depth-first
 * sequence, no recursion.  If violated, very bad things happen.
 * 
 * Use:
 * User app pre-allocates a large buffer and calls the initializer
 * Stack-heavy routines (RSA, EC) request a chunk of bytes at start of fn
 * **This request may fail, then users need to use alloca() and hope
 * At end of function call the deallocator
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "inner.h"

static uint8_t *stack_proxy = NULL;
static uint16_t stack_proxy_size = 0;
static uint16_t stack_proxy_ptr = 0;
static uint16_t stack_proxy_max_ptr = 0;
static uint8_t stack_proxy_depth = 0;
static uint16_t stack_proxy_start[16]; /* Max # of alive allocations */

void br_esp8266_stack_proxy_init(uint8_t *space, uint16_t size)
{
	stack_proxy = space;
	stack_proxy_size = size;
	stack_proxy_ptr = 0;
	stack_proxy_max_ptr = 0;
}

size_t br_esp8266_stack_proxy_max()
{
	return stack_proxy_max_ptr;
}

size_t br_esp8266_stack_proxy_usage()
{
	return stack_proxy_ptr;
}

void br_esp8266_stack_proxy_deinit()
{
	stack_proxy = NULL;
	stack_proxy_size = 0;
	stack_proxy_ptr = 0;
	stack_proxy_max_ptr = 0;
	stack_proxy_depth = 0;
}

/* Stores the current ptr to the size stack on function entry, before any allocs */
void br_stack_proxy_enter()
{
	if (!stack_proxy) return;
	stack_proxy_start[stack_proxy_depth++] = stack_proxy_ptr;
}

void *br_stack_proxy_alloc(size_t bytes)
{
	if (!stack_proxy) return NULL;

	if (stack_proxy_ptr + bytes <= stack_proxy_size) {
		uint8_t *ptr = &stack_proxy[stack_proxy_ptr];
		stack_proxy_ptr += bytes;
		if (stack_proxy_max_ptr < stack_proxy_ptr) {
			stack_proxy_max_ptr = stack_proxy_ptr;
		}
		while (stack_proxy_ptr&0x3) stack_proxy_ptr++; // Align 32-bits
		return (void*)ptr;
	}
	// If we're here, the 2nd stack allocation failed.  Record if in debug mode
	if (_debugBearSSL) {
		char a[32];
		sprintf(a,"stack2 alloc %d fail\n", bytes);
		_BearSSLSerialPrint(a);
	}
	return NULL;
}

void br_stack_proxy_exit()
{
	if (!stack_proxy) return;

	stack_proxy_ptr = stack_proxy_start[--stack_proxy_depth];
}

#endif
