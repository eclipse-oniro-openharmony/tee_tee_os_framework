/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ERROR_H
#define SaSi_ERROR_H

#include "ssi_pal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ! @file
@brief This module defines the error return code types and the numbering spaces of the error codes
for each module of the layers listed below.
*/

/* ! The definitions of the error number space used for the different modules */

/* ........... Error base numeric mapping definitions ................... */
/* ----------------------------------------------------------------------- */

/* The global error base number */
#define SaSi_ERROR_BASE 0x00F00000UL

/* The error range number assigned for each layer */
#define SaSi_ERROR_LAYER_RANGE 0x00010000UL

/* The error range number assigned to each module on its specified layer */
#define SaSi_ERROR_MODULE_RANGE 0x00000100UL

/* Defines the layer index for the error mapping */
#define SaSi_LAYER_ERROR_IDX 0UL
#define LLF_LAYER_ERROR_IDX  1UL
#define GENERIC_ERROR_IDX    5UL

/* Defines the module index for error mapping */
#define AES_ERROR_IDX  0x00UL
#define DES_ERROR_IDX  0x01UL
#define HASH_ERROR_IDX 0x02UL
#define HMAC_ERROR_IDX 0x03UL
#define RSA_ERROR_IDX  0x04UL
#define DH_ERROR_IDX   0x05UL

#define ECPKI_ERROR_IDX  0x08UL
#define RND_ERROR_IDX    0x0CUL
#define COMMON_ERROR_IDX 0x0DUL
#define KDF_ERROR_IDX    0x11UL
#define AESCCM_ERROR_IDX 0x15UL
#define FIPS_ERROR_IDX   0x17UL

#define PKA_MODULE_ERROR_IDX 0x21UL
#define CHACHA_ERROR_IDX     0x22UL

/* .......... defining the error spaces for each module on each layer ........... */
/* ------------------------------------------------------------------------------ */

/* AES module on the SaSi layer base address - 0x00F00000 */
#define SaSi_AES_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * AES_ERROR_IDX))

/* DES module on the SaSi layer base address - 0x00F00100 */
#define SaSi_DES_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * DES_ERROR_IDX))

/* HASH module on the SaSi layer base address - 0x00F00200 */
#define SaSi_HASH_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * HASH_ERROR_IDX))

/* HMAC module on the SaSi layer base address - 0x00F00300 */
#define SaSi_HMAC_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * HMAC_ERROR_IDX))

/* PKI RSA module on the SaSi layer base address - 0x00F00400 */
#define SaSi_RSA_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * RSA_ERROR_IDX))

/* DH module on the SaSi layer base address - 0x00F00500 */
#define SaSi_DH_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * DH_ERROR_IDX))

/* ECPKI module on the SaSi layer base address - 0x00F00800 */
#define SaSi_ECPKI_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * ECPKI_ERROR_IDX))

/* ECPKI module on the LLF layer base address -  0x00F10800 */
#define LLF_ECPKI_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * LLF_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * ECPKI_ERROR_IDX))

/* RND module on the SaSi layer base address - 0x00F00C00 */
#define SaSi_RND_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * RND_ERROR_IDX))

/* RND module on the LLF layer base address -  0x00F10C00 */
#define LLF_RND_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * LLF_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * RND_ERROR_IDX))

/* COMMMON module on the SaSi layer base address - 0x00F00D00 */
#define SaSi_COMMON_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * COMMON_ERROR_IDX))

/* KDF module on the SaSi layer base address - 0x00F01100 */
#define SaSi_KDF_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * KDF_ERROR_IDX))

/* AESCCM module on the SaSi layer base address - 0x00F01500 */
#define SaSi_AESCCM_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * AESCCM_ERROR_IDX))

/* FIPS module on the SaSi layer base address - 0x00F01700 */
#define SaSi_FIPS_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * FIPS_ERROR_IDX))

/* SELF TEST module on the SaSi layer base address - 0x00F02100 */
#define PKA_MODULE_ERROR_BASE                                            \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + \
     (SaSi_ERROR_MODULE_RANGE * PKA_MODULE_ERROR_IDX))

/* SELF TEST module on the SaSi layer base address -  */
#define SaSi_CHACHA_MODULE_ERROR_BASE \
    (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * SaSi_LAYER_ERROR_IDX) + (SaSi_ERROR_MODULE_RANGE * CHACHA_ERROR_IDX))

/* User generic layer base address - 0x00F50000 */
#define GENERIC_ERROR_BASE              (SaSi_ERROR_BASE + (SaSi_ERROR_LAYER_RANGE * GENERIC_ERROR_IDX))
#define SaSi_FATAL_ERROR                (GENERIC_ERROR_BASE + 0x00UL)
#define SaSi_OUT_OF_RESOURCE_ERROR      (GENERIC_ERROR_BASE + 0x01UL)
#define SaSi_ILLEGAL_RESOURCE_VAL_ERROR (GENERIC_ERROR_BASE + 0x02UL)

/* ............ The OK (success) definition ....................... */
#define SaSi_OK 0

#define SASI_SaSi_RETURN_ERROR(retCode, retcodeInfo, funcHandler) \
    ((retCode) == 0 ? SaSi_OK : funcHandler(retCode, retcodeInfo))

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* ! The typedef definition of all of the error codes that are returned from the SaSi functions */
typedef uint32_t SaSiError_t;

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
