# Description

oplzkwp is a library for ELF obfuscation. It uses PRESENT and blake244 to
encrypt your payload on the fly. Only the functions that are currently
executed are decrypted in memory. Both Linux (x86) and Android (ARM) are
supported.

# How To

Modify payload.c to fit your needs. Constraints:

  +  Each function starting with `_e_` will be encrypted and decrypted at
     run-time.

  +  Use `decrypt_and_call(next)` to call another `_e_` function. If the function
     is currently called (e.g., reentrant), a regular call must be done.

  +  Each functions needs to be page-aligned.
     (see payload.c and  `__attribute__((aligned(PAGE_SIZE))`).

  +  The final executable must be compiled with `-fpie` (this is the default if
     using the Makefile provided).

# Build

  + Linux, use `make`.

  + Android, use `make android` (You must have ndk-build setup).
    The executable will be in ./libs/armebi/

# Feeling lucky?

  Just run the provided `./oplzkwp`

