/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* !
@file
@brief This file contains all of the enums and definitions that are used for the
        CryptoCell Lib init and finish APIs, as well as the APIs themselves.
*/

#ifndef __SNS_SILIB_H__
#define __SNS_SILIB_H__

#include "ssi_pal_types.h"
#include "sasi_rnd.h"
#include "sasi_fips.h"

typedef enum {
    SA_SILIB_RET_OK = 0,
    SA_SILIB_RET_ENODEV,    /* Device not opened or does not exist */
    SA_SILIB_RET_EINTERNAL, /* Internal driver error (check system log) */
    SA_SILIB_RET_ENOTSUP,   /* Unsupported function/option */
    SA_SILIB_RET_ENOPERM,   /* Not enough permissions for request */
    SA_SILIB_RET_EINVAL,    /* Invalid parameters */
    SA_SILIB_RET_HW_Q_INIT,
    SA_SILIB_RET_COMPLETION,
    SA_SILIB_RET_HAL,
    SA_SILIB_RET_ASYM_ERR,
    SA_SILIB_RET_RND_INST_ERR,
    SA_SILIB_RET_EINVAL_HW_VERSION,   /* Invalid HW version */
    SA_SILIB_RET_EINVAL_HW_SIGNATURE, /* Invalid HW signature */
    SA_SILIB_RET_PAL,
    SA_SILIB_RET_EFIPS, /* fips tests error */
    SA_SILIB_RESERVE32B = 0x7FFFFFFFL
} SA_SilibRetCode_t;

#define DX_VERSION_PRODUCT_BIT_SHIFT 0x18UL
#define DX_VERSION_PRODUCT_BIT_SIZE  0x8UL

/* !
@brief This function Perform global initialization of the ARM TrustZone CryptoCell TEE runtime library;
it must be called once per cold boot cycle. As part of the global initialization the function verifies that
all the cryptographic engines are working as expected by running known answer tests. If a test fails (the function
returns an error), it signifies that there is a fatal error, and it should be handled accordingly.
Among other initializations, this function calls SaSi_RND_Instantiation and SaSi_RND_SetGenerateVectorFunc
to initialize the TRNG and the primary RND context. An initialized RND context is required for calling RND
APIs and asymmetric cryptography key generation and signatures. The primary context returned by this
function can be used as a single global context for all RND needs. Alternatively, other contexts may
be initialized and used with a more noted scope (for specific applications or specific threads).
\note The Mutexes, if used, are initialized by this API. Therefore, unlike the other APIs in the library,
this API is not thread-safe.
\note If the isFipsSupport flag is set to ON, the crypto APIs that follow (until the next cold boot) behave
according to FIPS certification restrictions. For example If one of the known answer tests returns an error, all other
cryptographic operations are disabled. For additional information see the ~!TEE Software Integration Guidelines - FIPS
Certification Support section.
@return SA_SILIB_RET_OK on success.
@return A non-zero value in case of failure.
*/
SA_SilibRetCode_t SaSi_LibInit(SaSi_RND_Context_t *rndContext_ptr, /* !< [in/out] Pointer to the RND context buffer,
                                   allocated by the user. The context is used to maintain the RND state as well as
                                   pointers to a function used for random vector generation. This context must be saved
                                   and provided as parameter to any API that uses the RND module. */
                               SaSi_RND_WorkBuff_t *rndWorkBuff_ptr /* !< [in] Scratchpad for the RND module's work */,
                               bool isFipsSupport, /* !< [in] true if FIPS mode ON is required */
                               SaSi_FipsKatContext_t *pFipsCtx /* !< [in] buffer used if FIPS mode is ON */);
/* !
@brief This function finalize the library operations. It frees the associated resources (mutexes) and call hal and pal
terminate functions. the function also call SaSi_RND_UnInstantiation to clean the rnd context.
@return SA_SILIB_RET_OK on success.
@return A non-zero value in case of failure.
*/
void SaSi_LibFini(
    SaSi_RND_Context_t
        *rndContext_ptr /* !< [in/out] Pointer to the RND context buffer that was initialized in SaSi_LibInit. */);

#endif /* __SNS_SILIB_H__ */
