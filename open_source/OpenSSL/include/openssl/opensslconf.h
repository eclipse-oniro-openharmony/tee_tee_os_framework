/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: openssl conf.
 * Author: gaobo794@huawei.com
 * Create: 2020-03-04
 */

#include <openssl/opensslv.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef OPENSSL_ALGORITHM_DEFINES
# error OPENSSL_ALGORITHM_DEFINES no longer supported
#endif

/*
 * OpenSSL was configured with the following options:
 */

#ifndef OPENSSL_NO_MD2
# define OPENSSL_NO_MD2
#endif
#ifndef OPENSSL_NO_RC5
# define OPENSSL_NO_RC5
#endif
#ifdef ADAPTOR_ENABLE
#ifdef OPENSSL_THREADS
# undef OPENSSL_THREADS
#endif
#ifndef OPENSSL_RAND_SEED_OS
# define OPENSSL_RAND_SEED_OS
#endif
#endif
#ifndef OPENSSL_NO_ASAN
# define OPENSSL_NO_ASAN
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
# define OPENSSL_NO_CRYPTO_MDEBUG
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# define OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
#endif
#ifndef OPENSSL_NO_DEVCRYPTOENG
# define OPENSSL_NO_DEVCRYPTOENG
#endif
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
# define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif
#ifndef OPENSSL_NO_EGD
# define OPENSSL_NO_EGD
#endif
#ifndef OPENSSL_NO_EXTERNAL_TESTS
# define OPENSSL_NO_EXTERNAL_TESTS
#endif
#ifndef OPENSSL_NO_FUZZ_AFL
# define OPENSSL_NO_FUZZ_AFL
#endif
#ifndef OPENSSL_NO_FUZZ_LIBFUZZER
# define OPENSSL_NO_FUZZ_LIBFUZZER
#endif
#ifndef OPENSSL_NO_HEARTBEATS
# define OPENSSL_NO_HEARTBEATS
#endif
#ifndef OPENSSL_NO_MSAN
# define OPENSSL_NO_MSAN
#endif
#ifndef OPENSSL_NO_SCTP
# define OPENSSL_NO_SCTP
#endif
#ifndef OPENSSL_NO_SSL_TRACE
# define OPENSSL_NO_SSL_TRACE
#endif
#ifndef OPENSSL_NO_SSL3
# define OPENSSL_NO_SSL3
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
# define OPENSSL_NO_SSL3_METHOD
#endif
#ifndef OPENSSL_NO_UBSAN
# define OPENSSL_NO_UBSAN
#endif
#ifndef OPENSSL_NO_UNIT_TEST
# define OPENSSL_NO_UNIT_TEST
#endif
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
# define OPENSSL_NO_WEAK_SSL_CIPHERS
#endif
#ifndef OPENSSL_NO_STATIC_ENGINE
# define OPENSSL_NO_STATIC_ENGINE
#endif


/*
 * Sometimes OPENSSSL_NO_xxx ends up with an empty file and some compilers
 * don't like that.  This will hopefully silence them.
 */
#define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/*
 * Applications should use -DOPENSSL_API_COMPAT=<version> to suppress the
 * declarations of functions deprecated in or before <version>. Otherwise, they
 * still won't see them if the library has been built to disable deprecated
 * functions.
 */
#ifndef DECLARE_DEPRECATED
# define DECLARE_DEPRECATED(f)   f;
#endif

#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

#ifndef OPENSSL_MIN_API
# define OPENSSL_MIN_API 0
#endif

#if !defined(OPENSSL_API_COMPAT) || OPENSSL_API_COMPAT < OPENSSL_MIN_API
# undef OPENSSL_API_COMPAT
# define OPENSSL_API_COMPAT OPENSSL_MIN_API
#endif

/*
 * Do not deprecate things to be deprecated in version 1.2.0 before the
 * OpenSSL version number matches.
 */
#if OPENSSL_VERSION_NUMBER < 0x10200000L
# define DEPRECATEDIN_1_2_0(f)   f;
#elif OPENSSL_API_COMPAT < 0x10200000L
# define DEPRECATEDIN_1_2_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_2_0(f) f;
#endif

#if OPENSSL_API_COMPAT < 0x10100000L
# define DEPRECATEDIN_1_1_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_1_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x10000000L
# define DEPRECATEDIN_1_0_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_0_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x00908000L
# define DEPRECATEDIN_0_9_8(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_0_9_8(f)
#endif

/* Generate 80386 code? */
#undef I386_ONLY

#undef OPENSSL_UNISTD
#define OPENSSL_UNISTD <unistd.h>

#undef OPENSSL_EXPORT_VAR_AS_FUNCTION

/*
 * The following are cipher-specific, but are part of the public API.
 */
#  if defined(__arm) || defined(__arm__)
#  define THIRTY_TWO_BIT
#  undef SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  elif defined(__aarch64__)
#  undef SIXTY_FOUR_BIT_LONG
#  undef THIRTY_TWO_BIT
#  define SIXTY_FOUR_BIT
#  endif
#define RC4_INT unsigned int

#ifndef __STDC_NO_ATOMICS__
# define __STDC_NO_ATOMICS__
#endif
#ifndef OPENSSL_NO_ENGINE
# define OPENSSL_NO_ENGINE
#endif
#ifndef OPENSSL_NO_POLY1305
# define OPENSSL_NO_POLY1305
#endif
#ifndef OPENSSL_NO_DSA
# define OPENSSL_NO_DSA
#endif
#ifndef OPENSSL_NO_SCRYPT
# define OPENSSL_NO_SCRYPT
#endif
#ifndef OPENSSL_NO_SIPHASH
# define OPENSSL_NO_SIPHASH
#endif
#ifndef OPENSSL_NO_CAMELLIA
# define OPENSSL_NO_CAMELLIA
#endif
#ifndef OPENSSL_NO_CHACHA
# define OPENSSL_NO_CHACHA
#endif
#ifndef OPENSSL_NO_RC4
# define OPENSSL_NO_RC4
#endif
#ifndef OPENSSL_NO_MD4
# define OPENSSL_NO_MD4
#endif
#ifndef OPENSSL_NO_IDEA
# define OPENSSL_NO_IDEA
#endif
#ifndef OPENSSL_NO_RC2
# define OPENSSL_NO_RC2
#endif
#ifndef OPENSSL_NO_BF
# define OPENSSL_NO_BF
#endif
#ifndef OPENSSL_NO_CAST
# define OPENSSL_NO_CAST
#endif
#ifndef OPENSSL_NO_MDC2
# define OPENSSL_NO_MDC2
#endif
#ifndef OPENSSL_NO_RMD160
# define OPENSSL_NO_RMD160
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
# define OPENSSL_NO_WHIRLPOOL
#endif
#ifndef OPENSSL_USE_NODELETE
# define OPENSSL_USE_NODELETE
#endif
#ifndef OPENSSL_NO_COMP
# define OPENSSL_NO_COMP
#endif
#ifndef OPENSSL_NO_TS
# define OPENSSL_NO_TS
#endif
#ifndef OPENSSL_NO_OCSP
# define OPENSSL_NO_OCSP
#endif
#ifndef OPENSSL_NO_POSIX_IO
# define OPENSSL_NO_POSIX_IO
#endif
#ifndef OPENSSL_NO_STDIO
# define OPENSSL_NO_STDIO
#endif
#ifndef OPENSSL_NO_CT
# define OPENSSL_NO_CT
#endif
#ifndef CONFIG_OPENSSL_NO_ASM
#ifndef SHA1_ASM
# define SHA1_ASM
#endif
#ifndef SHA256_ASM
# define SHA256_ASM
#endif
#ifndef SHA512_ASM
# define SHA512_ASM
#endif
#ifndef ECP_NISTZ256_ASM
# define ECP_NISTZ256_ASM
#endif
#ifndef OPENSSL_BN_ASM_MONT
# define OPENSSL_BN_ASM_MONT
#endif
#endif
#ifndef OPENSSL_NO_CMS
# define OPENSSL_NO_CMS
#endif
#ifndef OPENSSL_NO_ERR
# define OPENSSL_NO_ERR
#endif
#ifndef OPENSSL_NO_BLAKE2
# define OPENSSL_NO_BLAKE2
#endif
#ifndef OPENSSL_NO_ARIA
# define OPENSSL_NO_ARIA
#endif
#ifndef OPENSSL_NO_SEED
# define OPENSSL_NO_SEED
#endif
#ifndef OPENSSL_NO_DGRAM
# define OPENSSL_NO_DGRAM
#endif
#ifndef OPENSSL_NO_SOCK
# define OPENSSL_NO_SOCK
#endif
#ifndef OPENSSL_NO_OCB
# define OPENSSL_NO_OCB
#endif
#ifndef OPENSSL_NO_DH
# define OPENSSL_NO_DH
#endif

#ifdef  __cplusplus
}
#endif
