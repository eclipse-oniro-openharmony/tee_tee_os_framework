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

/*!
@file
@brief This file contains all of the enums and definitions that are used for the
        CryptoCell Lib init and finish APIs, as well as the APIs themselves.
*/

#ifndef __CC_LIB_H__
#define __CC_LIB_H__

#include "cc_pal_types.h"
#include "cc_rnd.h"
#include "cc_fips.h"

typedef enum {
	CC_LIB_RET_OK = 0,
	SA_SILIB_RET_ENODEV,        /* Device not opened or does not exist */
	SA_SILIB_RET_EINTERNAL,     /* Internal driver error (check system log) */
	SA_SILIB_RET_ENOTSUP,       /* Unsupported function/option */
	SA_SILIB_RET_ENOPERM,       /* Not enough permissions for request */
	SA_SILIB_RET_EINVAL,        /* Invalid parameters */
	SA_SILIB_RET_HW_Q_INIT,
	SA_SILIB_RET_COMPLETION,
	CC_LIB_RET_HAL,
	SA_SILIB_RET_ASYM_ERR,
	CC_LIB_RET_RND_INST_ERR,
	CC_LIB_RET_EINVAL_HW_VERSION,    /* Invalid HW version */
	CC_LIB_RET_EINVAL_HW_SIGNATURE,  /* Invalid HW signature */
	CC_LIB_RET_PAL,
        SA_SILIB_RET_EFIPS,		/* fips tests error */
	CC_LIB_RESERVE32B = 0x7FFFFFFFL
} CClibRetCode_t;


#define DX_VERSION_PRODUCT_BIT_SHIFT 	0x18UL
#define DX_VERSION_PRODUCT_BIT_SIZE 	0x8UL

/*!
@brief This function Perform global initialization of the ARM TrustZone CryptoCell TEE runtime library;
it must be called once per cold boot cycle. As part of the global initialization the function verifies that
all the cryptographic engines are working as expected by running known answer tests. If a test fails (the function
returns an error), it signifies that there is a fatal error, and it should be handled accordingly.
Among other initializations, this function calls CC_RndInstantiation and CC_RndSetGenerateVectorFunc
to initialize the TRNG and the primary RND context. An initialized RND context is required for calling RND
APIs and asymmetric cryptography key generation and signatures. The primary context returned by this
function can be used as a single global context for all RND needs. Alternatively, other contexts may
be initialized and used with a more noted scope (for specific applications or specific threads).
\note The Mutexes, if used, are initialized by this API. Therefore, unlike the other APIs in the library,
this API is not thread-safe. \par
\note If the isFipsSupport flag is set to ON, the crypto APIs that follow (until the next cold boot) behave
according to FIPS certification restrictions. For example If one of the known answer tests returns an error, all other
cryptographic operations are disabled. For additional information see the ~!TEE Software Integration Guidelines - FIPS
Certification Support section.
@return CC_LIB_RET_OK on success.
@return A non-zero value in case of failure.
*/
CClibRetCode_t CC_LibInit(CCRndContext_t  *rndContext_ptr, /*!< [in/out] Pointer to the RND context buffer,
									allocated by the user. The context is used to maintain the RND state as well as
									pointers to a function used for random vector generation. This context must be saved and
									provided as parameter to any API that uses the RND module.*/
			       CCRndWorkBuff_t  *rndWorkBuff_ptr /*!< [in] Scratchpad for the RND module's work */,
                               bool isFipsSupport, /*!< [in] true if FIPS mode ON is required */
			       CCFipsKatContext_t  *pFipsCtx  /*!< [in] buffer used if FIPS mode is ON (may be NULL for all other cases). */);
/*!
@brief This function finalize the library operations. It frees the associated resources (mutexes) and call hal and pal terminate functions.
the function also call CC_RndUnInstantiation to clean the rnd context.
@return CC_LIB_RET_OK on success.
@return A non-zero value in case of failure.
*/
void CC_LibFini(CCRndContext_t  *rndContext_ptr /*!< [in/out] Pointer to the RND context buffer that was initialized in CC_LibInit.*/);


#endif /*__CC_LIB_H__*/

