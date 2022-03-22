/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef _CRYPTO_DRIVER_DEFS_H
#define _CRYPTO_DRIVER_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dx_pal_types_plat.h"
#include "secureboot_defs.h"
/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

/* The AES block size in words and in bytes */
#define AES_BLOCK_SIZE_IN_WORDS 4
#define AES_BLOCK_SIZE_IN_BYTES (AES_BLOCK_SIZE_IN_WORDS * sizeof(uint32_t))

/* The size of the IV or counter buffer */
#define AES_IV_COUNTER_SIZE_IN_WORDS AES_BLOCK_SIZE_IN_WORDS
#define AES_IV_COUNTER_SIZE_IN_BYTES (AES_IV_COUNTER_SIZE_IN_WORDS * sizeof(uint32_t))

/* The size of the AES KEY in words and bytes */
#define AES_KEY_SIZE_IN_WORDS AES_BLOCK_SIZE_IN_WORDS
#define AES_KEY_SIZE_IN_BYTES (AES_KEY_SIZE_IN_WORDS * sizeof(uint32_t))

#define AES_Key128Bits_SIZE_IN_WORDS AES_BLOCK_SIZE_IN_WORDS
#define AES_Key128Bits_SIZE_IN_BYTES AES_BLOCK_SIZE_IN_BYTES
#define AES_Key256Bits_SIZE_IN_WORDS 8
#define AES_Key256Bits_SIZE_IN_BYTES (AES_Key256Bits_SIZE_IN_WORDS * sizeof(uint32_t))

/* Hash IV+Length */
#define HASH_DIGEST_SIZE_IN_WORDS 8
#define HASH_DIGEST_SIZE_IN_BYTES (HASH_DIGEST_SIZE_IN_WORDS * sizeof(uint32_t))
#define HASH_LENGTH_SIZE_IN_WORDS 4
#define HASH_LENGTH_SIZE_IN_BYTES (HASH_LENGTH_SIZE_IN_WORDS * sizeof(uint32_t))

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

#define NVM_HASH_Result_t HASH_Result_t

/* Defines the IV counter buffer  - 16 bytes array */
typedef uint32_t AES_Iv_t[AES_IV_COUNTER_SIZE_IN_WORDS];

/* Defines the AES key buffer */
typedef uint32_t AES_Key_t[AES_KEY_SIZE_IN_WORDS];

/* Defines the AES CMAC output result */
typedef uint8_t AES_CMAC_RESULT_t[AES_BLOCK_SIZE_IN_BYTES];

typedef enum {
    CRYPTO_DRIVER_HASH_MODE         = 0,
    CRYPTO_DRIVER_AES_CTR_MODE      = 1,
    CRYPTO_DRIVER_HASH_AES_CTR_MODE = 2,
} CryptoDriverMode_t;

/* enum definitons for crypto operation completion mode */
typedef enum {
    DX_SB_CRYPTO_COMPLETION_NO_WAIT         = 0,
    DX_SB_CRYPTO_COMPLETION_NO_WAIT_ASK_ACK = 1,
    DX_SB_CRYPTO_COMPLETION_WAIT_UPON_START = 2,
    DX_SB_CRYPTO_COMPLETION_WAIT_UPON_END   = 3
} DX_SB_CryptoCompletionMode_t;

/* *****************************************************************************
 *                 HW engines related definitions
 * *************************************************************************** */
enum DX_SB_HashPadding {
    DX_SB_HASH_PADDING_DISABLED            = 0,
    DX_SB_HASH_PADDING_ENABLED             = 1,
    DX_SB_HASH_DIGEST_RESULT_LITTLE_ENDIAN = 2,
    DX_SB_HASH_PADDING_RESERVE32           = INT32_MAX,
};

#define CONVERT_TO_ADDR(ptr) (unsigned long)(ptr)

#ifdef __cplusplus
}
#endif

#endif
