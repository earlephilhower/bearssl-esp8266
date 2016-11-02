# Disclaimer

BearSSL is for now considered alpha-level software. This means that it
probably still has some bugs, possibly very serious ones (e.g. buffer
overflows -- one of the perks of using C as programming language). It
still lacks some functionalities. The API will probably change and may
break both source and binary compatibility.

In other words, you would be quite mad to use it for any production
purpose. Right now, this is for learning, testing and possibly
contributing.

The usage license is explicited in the `LICENSE.txt` file. This is the
"MIT license". It can be summarised in the following way:

 - You can use and reuse the library as you wish, and modify it, and
   integrate it in your own code, and distribute it as is or in any
   modified form, and so on.

 - The only obligation that the license terms put upon you is that you
   acknowledge and make it clear that if anything breaks, it is not my
   fault, and I am not liable for anything, regardless of the type and
   amount of collateral damage. The license terms say that the copyright
   notice "shall be included in all copies or substantial portions of
   the Software": this is how the disclaimer is "made explicit".
   Basically, I have put it in every source file, so just keep it there.

# Installation

As of version 0.1, BearSSL is a simple static library. Most of the
process is rather manual and old-style, and there is no installer (this
will be added in a later version, in particular when all the man pages
for BearSSL functions are written).

 1. Have a look at the top of the `Makefile`. There you can configure the
    command names and flags for invoking the C compiler, linker, and
    static library archiver.

 2. There are a few configurable switches in `src/config.h`. These switches
    relate to compile-time options, e.g. support of a system-provided
    random source. On usual platforms (e.g. Linux or OS X), auto-detection
    should work, but you can always override things with `config.h`.

 3. Type `make`. This should produce the static library (`libbearssl.a`),
    the test executables (`testcrypto`, `testspeed` and `testx509`), and
    the command-line debug tool (`brssl`). You might want to run the tests:

     - `testcrypto all` runs the cryptographic tests (test vectors on all
       implemented cryptogaphic functions). It can be slow.

     - `testspeed all` runs a number of performance benchmarks, there again
       on cryptographic functions. It gives a taste of how things go on the
       current platform.

     - `testx509` runs X.509 validation tests. The test certificates are
       all in `test/x509/`.

 4. The `brssl` command-line tool is a stand-alone binary. It can exercise
    some of the functionalities of BearSSL, in particular running a test
    SSL client or server. It is not meant for production purposes (e.g.
    the SSL client has a mode where it disregards the inability to validate
    the server's certificate, which is inherently unsafe, but convenient
    for debug).

 5. Using the library means writing some application code that invokes it,
    and linking with the static library. The header files are all in the
    `inc` directory; copy them wherever makes sense (e.g. in the
    `/usr/local/include` directory). The library itself (`libbearssl.a`)
    is what you link against.

    Alternatively, you may want to copy the source files directly into
    your own application code. This will make integrating ulterior versions
    of BearSSL more difficult. If you still want to go down that road,
    then simply copy all the `*.h` and `*.c` files from the `src` and `inc`
    directories into your application source code. In the BearSSL source
    archive, the source files are segregated into various sub-directories,
    but this is for my convenience only. There is no technical requirement
    for that, and all files can be dumped together in a simple directory.

    Dependencies are simple and systematic:

     - Each `*.c` file includes `inner.h`
     - `inner.h` includes `config.h` and `bearssl.h`
     - `bearssl.h` includes the other `bearssl_*.h`

# Versioning

I follow this simple version numbering scheme:

 - Version numbers are `x.y` or `x.y.z` where `x`, `y` ans `z` are
   decimal integers (possibly greater than 10). When the `.z` part is
   missing, it is equivalent to `.0`.

 - Backward compatibility is maintained, at both source and binary levels,
   for each major version: this means that if some application code was
   designed for version `x.y`, then it should compile, link and run
   properly with any version `x.y'` for any `y'` greater than `y`.

   The major version `0` is an exception. You shall not expect that any
   version that starts with `0.` offers any kind of compatibility,
   either source or binary, with any other `0.` version. (Of course I
   will try to maintain some decent level of source compatibility, but I
   make no promise in that respect. Since the API uses caller-allocated
   context structures, I already know that binary compatibility _will_
   be broken.)

 - Sub-versions (the `y` part) are about added functionality. That is,
   it can be expected that `1.3` will contain some extra functions when
   compared to `1.2`. The next version level (the `z` part) is for
   bugfixes that do not add any functionality.

# API Usage

Right now there is little documentation. The following principles are
maintained:

 - All public symbols (global functions and data elements, macros) have
   a name that starts with `br_` or `BR_`.

 - The header files (the `bearssl_*.h` in the `inc` directory) contain
   for now the most complete documentation (as comments).

 - Context structures are allocated by the caller. BearSSL does not
   contain any single `malloc()` call; this means that there is no
   "freeing up" call to be done. When you don't need some BearSSL
   functionality, just cease to call it, and that's it.

 - BearSSL contains no modifiable static data. It is thus thread-safe
   and reentrant, _for distinct contexts_. Accessing the same context
   structure from distinct threads, though, is a recipe for disaster.

 - The main SSL I/O API is organised as a state machine. A running
   SSL engine (client or server) has four I/O ports:

    - It can receive bytes from the transport medium ("record data").
    - It can send bytes to the transport medium.
    - It can receive application data, to be sent to the peer through
      the SSL tunnel.
    - It can produce application data, built from the records sent by
      the peer.

   BearSSL never performs I/O by itself; it expects the caller to
   provide or retrieve the data. Each port consists in a pair of
   functions: one yields the pointer to the buffer from which data
   can be read or to which data can be written, and the maximum
   size for such an operation; the other function is used to
   inform the engine about how many bytes were actually read or
   written.

   For instance, if the `br_ssl_engine_sendrec_buf()` function returns a
   non-NULL pointer, then this means that there are bytes to be sent to
   the transport medium. When the caller has indeed sent some or all of
   these bytes, it informs the engine with
   `br_ssl_engine_sendrec_ack()`.

   This state-machine API means that the engine never blocks. Each
   invocation may trigger computations, but will always return as
   promptly as the CPU power allows. All the I/O waiting is supposed to
   be done on the outside. This structure allows managing several
   concurrent SSL engines, along with other I/O tasks, with a single
   mono-threaded loop using `select()` or `poll()`. It also makes it
   easier to integrate BearSSL with various transport mechanisms (e.g.
   messages in the EAP-TLS authentication framework).

 - Nevertheless, there are situations where simple blocking calls _can_
   be used, and are convenient. For these situations, use the
   `br_sslio_context` wrapper. Then do blocking reads and writes with
   `br_sslio_read()` and similar functions. The sample client code
   in `samples/client_basic.c` shows how such things are done.
