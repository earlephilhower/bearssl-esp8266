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

#ifndef CONFIG_H__
#define CONFIG_H__

/*
 * This file contains compile-time flags that can override the
 * autodetection performed in relevant files. Each flag is a macro; it
 * deactivates the feature if defined to 0, activates it if defined to a
 * non-zero integer (normally 1). If the macro is not defined, then
 * autodetection applies.
 */

/*
 * When BR_64 is enabled, 64-bit integer types are assumed to be
 * efficient (i.e. the architecture has 64-bit registers and can
 * do 64-bit operations as fast as 32-bit operations).
 *
#define BR_64   1
 */

/*
 * When BR_SLOW_MUL is enabled, multiplications are assumed to be
 * substantially slow with regards to other integer operations, thus
 * making it worth to make more operations for a given task if it allows
 * using less multiplications.
 *
#define BR_SLOW_MUL   1
 */

/*
 * When BR_SLOW_MUL15 is enabled, short multplications (on 15-bit words)
 * are assumed to be substantially slow with regards to other integer
 * operations, thus making it worth to make more integer operations if
 * it allows using less multiplications.
 *
#define BR_SLOW_MUL15   1
 */

/*
 * When BR_CT_MUL31 is enabled, multiplications of 31-bit values (used
 * in the "i31" big integer implementation) use an alternate implementation
 * which is slower and larger than the normal multiplication, but should
 * ensure constant-time multiplications even on architectures where the
 * multiplication opcode takes a variable number of cycles to complete.
 *
#define BR_CT_MUL31   1
 */

/*
 * When BR_CT_MUL15 is enabled, multiplications of 15-bit values (held
 * in 32-bit words) use an alternate implementation which is slower and
 * larger than the normal multiplication, but should ensure
 * constant-time multiplications on most/all architectures where the
 * basic multiplication is not constant-time.
#define BR_CT_MUL15   1
 */

/*
 * When BR_NO_ARITH_SHIFT is enabled, arithmetic right shifts (with sign
 * extension) are performed with a sequence of operations which is bigger
 * and slower than a simple right shift on a signed value. This avoids
 * relying on an implementation-defined behaviour. However, most if not
 * all C compilers use sign extension for right shifts on signed values,
 * so this alternate macro is disabled by default.
#define BR_NO_ARITH_SHIFT   1
 */

/*
 * When BR_USE_URANDOM is enabled, the SSL engine will use /dev/urandom
 * to automatically obtain quality randomness for seedings its internal
 * PRNG.
 *
#define BR_USE_URANDOM   1
 */

/*
 * When BR_USE_WIN32_RAND is enabled, the SSL engine will use the Win32
 * (CryptoAPI) functions (CryptAcquireContext(), CryptGenRandom()...) to
 * automatically obtain quality randomness for seedings its internal PRNG.
 *
 * Note: if both BR_USE_URANDOM and BR_USE_WIN32_RAND are defined, the
 * former takes precedence.
 *
#define BR_USE_WIN32_RAND   1
 */

/*
 * When BR_USE_UNIX_TIME is enabled, the X.509 validation engine obtains
 * the current time from the OS by calling time(), and assuming that the
 * returned value (a 'time_t') is an integer that counts time in seconds
 * since the Unix Epoch (Jan 1st, 1970, 00:00 UTC).
 *
#define BR_USE_UNIX_TIME   1
 */

/*
 * When BR_USE_WIN32_TIME is enabled, the X.509 validation engine obtains
 * the current time from the OS by calling the Win32 function
 * GetSystemTimeAsFileTime().
 *
 * Note: if both BR_USE_UNIX_TIME and BR_USE_WIN32_TIME are defined, the
 * former takes precedence.
 *
#define BR_USE_WIN32_TIME   1
 */

#endif
