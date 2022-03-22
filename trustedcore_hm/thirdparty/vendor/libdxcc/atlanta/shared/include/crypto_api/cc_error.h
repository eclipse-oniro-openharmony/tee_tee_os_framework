/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_ERROR_H
#define _CC_ERROR_H

#include "cc_pal_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*! @file
@brief This file defines the error return code types and the numbering spaces of the error codes
for each module of the layers listed below.
*/

/*! The definitions of the error number space used for the different modules */

/* ........... Error base numeric mapping definitions ................... */
/* ----------------------------------------------------------------------- */

 /* The global error base number */
#define CC_ERROR_BASE          0x00F00000UL

/* The error range number assigned for each layer */
#define CC_ERROR_LAYER_RANGE   0x00010000UL

/* The error range number assigned to each module on its specified layer */
#define CC_ERROR_MODULE_RANGE  0x00000100UL

/* Defines the layer index for the error mapping */
#define CC_LAYER_ERROR_IDX     0x00UL
#define LLF_LAYER_ERROR_IDX      0x01UL
#define GENERIC_ERROR_IDX        0x05UL

/* Defines the module index for error mapping */
#define AES_ERROR_IDX            0x00UL
#define DES_ERROR_IDX            0x01UL
#define HASH_ERROR_IDX           0x02UL
#define HMAC_ERROR_IDX           0x03UL
#define RSA_ERROR_IDX            0x04UL
#define DH_ERROR_IDX             0x05UL

#define ECPKI_ERROR_IDX          0x08UL
#define RND_ERROR_IDX            0x0CUL
#define COMMON_ERROR_IDX         0x0DUL
#define KDF_ERROR_IDX            0x11UL
#define HKDF_ERROR_IDX           0x12UL
#define AESCCM_ERROR_IDX         0x15UL
#define FIPS_ERROR_IDX           0x17UL

#define PKA_MODULE_ERROR_IDX     0x21UL
#define CHACHA_ERROR_IDX         0x22UL
#define EC_MONT_EDW_ERROR_IDX    0x23UL
#define CHACHA_POLY_ERROR_IDX    0x24UL
#define POLY_ERROR_IDX         	 0x25UL
#define SRP_ERROR_IDX         	 0x26UL



/* .......... defining the error spaces for each module on each layer ........... */
/* ------------------------------------------------------------------------------ */

/*! AES module on the CryptoCell layer base address - 0x00F00000 */
#define CC_AES_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * AES_ERROR_IDX ) )

/*! DES module on the CryptoCell layer base address - 0x00F00100 */
#define CC_DES_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * DES_ERROR_IDX ) )

/*! HASH module on the CryptoCell layer base address - 0x00F00200 */
#define CC_HASH_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * HASH_ERROR_IDX ) )

/*! HMAC module on the CryptoCell layer base address - 0x00F00300 */
#define CC_HMAC_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * HMAC_ERROR_IDX ) )

/*! PKI RSA module on the CryptoCell layer base address - 0x00F00400 */
#define CC_RSA_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                   (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                   (CC_ERROR_MODULE_RANGE * RSA_ERROR_IDX ) )

/*! DH module on the CryptoCell layer base address - 0x00F00500 */
#define CC_DH_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                   (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                   (CC_ERROR_MODULE_RANGE * DH_ERROR_IDX ) )

/*! ECPKI module on the CryptoCell layer base address - 0x00F00800 */
#define CC_ECPKI_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * ECPKI_ERROR_IDX ) )

/*! ECPKI module on the LLF layer base address -  0x00F10800 */
#define LLF_ECPKI_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * LLF_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * ECPKI_ERROR_IDX ) )

/*! RND module on the CryptoCell layer base address - 0x00F00C00 */
#define CC_RND_MODULE_ERROR_BASE   (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * RND_ERROR_IDX ) )

/*! RND module on the LLF layer base address -  0x00F10C00 */
#define LLF_RND_MODULE_ERROR_BASE    (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * LLF_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * RND_ERROR_IDX ) )

/*! COMMMON module on the CryptoCell layer base address - 0x00F00D00 */
#define CC_COMMON_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                     (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                     (CC_ERROR_MODULE_RANGE * COMMON_ERROR_IDX ) )

/*! KDF module on the CryptoCell layer base address - 0x00F01100 */
#define CC_KDF_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                  (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                  (CC_ERROR_MODULE_RANGE * KDF_ERROR_IDX ) )

/*! KDF module on the CryptoCelllayer base address - 0x00F01100 */
#define CC_HKDF_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                  (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                  (CC_ERROR_MODULE_RANGE * HKDF_ERROR_IDX ) )

/*! AESCCM module on the CryptoCell layer base address - 0x00F01500 */
#define CC_AESCCM_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
	                                   (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
	                                   (CC_ERROR_MODULE_RANGE * AESCCM_ERROR_IDX ) )

/*! FIPS module on the CryptoCell layer base address - 0x00F01700 */
#define CC_FIPS_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
	                                   (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
	                                   (CC_ERROR_MODULE_RANGE * FIPS_ERROR_IDX ) )

/*! PKA module on the CryptoCell layer base address - 0x00F02100 */
#define PKA_MODULE_ERROR_BASE	          (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * PKA_MODULE_ERROR_IDX ) )

/*! CHACHA module on the CryptoCell layer base address -  */
#define CC_CHACHA_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * CHACHA_ERROR_IDX ) )
/*! CC_EC_MONT_EDW module on the CryptoCell layer base address -  */
#define CC_EC_MONT_EDW_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * EC_MONT_EDW_ERROR_IDX ) )

/*! CHACHA POLY module on the CryptoCell layer base address -  */
#define CC_CHACHA_POLY_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * CHACHA_POLY_ERROR_IDX ) )
/*! POLY module on the CryptoCell layer base address -  */
#define CC_POLY_MODULE_ERROR_BASE  (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * POLY_ERROR_IDX ) )

/*! SRP module on the CryptoCell layer base address -  */
#define CC_SRP_MODULE_ERROR_BASE (CC_ERROR_BASE + \
                                           (CC_ERROR_LAYER_RANGE * CC_LAYER_ERROR_IDX) + \
                                           (CC_ERROR_MODULE_RANGE * SRP_ERROR_IDX ) )
/* User generic layer base address - 0x00F50000 */
#define GENERIC_ERROR_BASE ( CC_ERROR_BASE + (CC_ERROR_LAYER_RANGE * GENERIC_ERROR_IDX) )
#define CC_FATAL_ERROR			(GENERIC_ERROR_BASE + 0x00UL)
#define CC_OUT_OF_RESOURCE_ERROR		(GENERIC_ERROR_BASE + 0x01UL)
#define CC_ILLEGAL_RESOURCE_VAL_ERROR		(GENERIC_ERROR_BASE + 0x02UL)



/* ............ The OK (success) definition ....................... */


#define CC_CRYPTO_RETURN_ERROR(retCode, retcodeInfo, funcHandler) \
	((retCode) == 0 ? CC_OK : funcHandler(retCode, retcodeInfo))

/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/

#ifdef __cplusplus
}
#endif

#endif




