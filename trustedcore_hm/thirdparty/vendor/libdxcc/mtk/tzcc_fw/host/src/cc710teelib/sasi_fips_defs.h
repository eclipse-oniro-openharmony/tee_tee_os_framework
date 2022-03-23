/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_FIPS_DEFS_H
#define _SaSi_FIPS_DEFS_H

#include "sasi_fips.h"
#include "sasi_fips_error.h"
#include "sasi_fips_rsa_defs.h"
#include "sasi_fips_ecc_defs.h"

typedef enum CC_FipsTrace_t {
    CC_FIPS_TRACE_NONE       = 0x0,
    CC_FIPS_TRACE_AES_PUT    = 0x1,
    CC_FIPS_TRACE_AESCCM_PUT = 0x2,
    CC_FIPS_TRACE_DES_PUT    = 0x4,
    CC_FIPS_TRACE_HASH_PUT   = 0x8,
    CC_FIPS_TRACE_HMAC_PUT   = 0x10,
    CC_FIPS_TRACE_RSA_PUT    = 0x20,
    CC_FIPS_TRACE_ECDSA_PUT  = 0x40,
    CC_FIPS_TRACE_DH_PUT     = 0x80,
    CC_FIPS_TRACE_ECDH_PUT   = 0x100,
    CC_FIPS_TRACE_PRNG_PUT   = 0x200,
    CC_FIPS_TRACE_RSA_COND   = 0x400,
    CC_FIPS_TRACE_ECC_COND   = 0x800,
    CC_FIPS_TRACE_PRNG_CONT  = 0x1000,
    CC_FIPS_TRACE_RESERVE32B = INT32_MAX
} CC_FipsTrace_t;

#ifdef SSI_SUPPORT_FIPS

typedef struct CC_FipsStateData {
    CC_FipsState_t state;
    CC_FipsError_t error;
    CC_FipsTrace_t trace;
} CC_FipsStateData_t;

// used for every SaSi API. If FIPS error is on, return with FIPS error code
#define CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR()                                                   \
    {                                                                                            \
        CC_FipsState_t fipsState;                                                                \
        if (FipsGetRawState(&fipsState) != SaSi_OK) {                                            \
            return SaSi_FIPS_ERROR;                                                              \
        }                                                                                        \
        if ((fipsState & CC_FIPS_STATE_ERROR) || !(fipsState & CC_FIPS_STATE_CRYPTO_APPROVED)) { \
            return SaSi_FIPS_ERROR;                                                              \
        }                                                                                        \
    }

// used for SaSi API that returns void. If FIPS error is on, return with no operation
#define CHECK_AND_RETURN_UPON_FIPS_ERROR()                                                       \
    {                                                                                            \
        CC_FipsState_t fipsState;                                                                \
        if (FipsGetRawState(&fipsState) != SaSi_OK) {                                            \
            return;                                                                              \
        }                                                                                        \
        if ((fipsState & CC_FIPS_STATE_ERROR) || !(fipsState & CC_FIPS_STATE_CRYPTO_APPROVED)) { \
            return;                                                                              \
        }                                                                                        \
    }

// used for conditional testing. If FIPS state is not FIPS_SUPPORT return with OK
#define CHECK_AND_RETURN_UPON_FIPS_STATE()            \
    {                                                 \
        CC_FipsState_t fipsState;                     \
        if (FipsGetRawState(&fipsState) != SaSi_OK) { \
            return SaSi_FIPS_ERROR;                   \
        }                                             \
        if (!(fipsState & CC_FIPS_STATE_SUPPORTED)) { \
            return SaSi_OK;                           \
        }                                             \
    }

#define CHECK_FIPS_SUPPORTED(supported)                                                                  \
    {                                                                                                    \
        CC_FipsState_t fipsState;                                                                        \
        supported = ((FipsGetRawState(&fipsState) != SaSi_OK) || (fipsState & CC_FIPS_STATE_SUPPORTED)); \
    }

#define FIPS_RSA_VALIDATE(pRndContext, pCcUserPrivKey, pCcUserPubKey, pFipsCtx) \
    SaSi_FipsRsaConditionalTest(pRndContext, pCcUserPrivKey, pCcUserPubKey, pFipsCtx)

#define FIPS_ECC_VALIDATE(pRndContext, pUserPrivKey, pUserPublKey, pFipsCtx) \
    SaSi_FipsEccConditionalTest(pRndContext, pUserPrivKey, pUserPublKey, pFipsCtx)

#define SaSi_FIPS_SET_RND_CONT_ERR()                                                             \
    {                                                                                            \
        CC_FipsState_t fipsState;                                                                \
        if ((FipsGetRawState(&fipsState) != SaSi_OK) || (fipsState & CC_FIPS_STATE_SUPPORTED)) { \
            (void)FipsSetError(CC_TEE_FIPS_ERROR_PRNG_CONT);                                     \
        }                                                                                        \
    }

CC_FipsError_t FipsGetTrace(CC_FipsTrace_t *pFipsTrace); /* !< [out]The fips Trace of the library. */
CC_FipsError_t FipsSetState(CC_FipsState_t fipsState);   /* !< [in] Sets the fips State of the library. */
SaSiError_t FipsGetRawState(CC_FipsState_t *pFipsState); /* !< [out] The fips State of the library. */
SaSiError_t FipsRevertState(CC_FipsState_t fipsState);   /* !< [in] The fips State that should be reverted. */
CC_FipsError_t FipsSetError(CC_FipsError_t fipsError);   /* !< [in] Sets the fips Error of the library. */
CC_FipsError_t FipsSetTrace(CC_FipsTrace_t fipsTrace);   /* !< [in] Sets the fips Trace of the library. */

CC_FipsError_t FipsRunPowerUpTest(SaSi_RND_Context_t *rndContext_ptr, SaSi_FipsKatContext_t *pFipsCtx);
CC_FipsError_t SaSi_FipsAesRunTests(void);
CC_FipsError_t SaSi_FipsAesCcmRunTests(void);
CC_FipsError_t SaSi_FipsDesRunTests(void);
CC_FipsError_t SaSi_FipsHashRunTests(void);
CC_FipsError_t SaSi_FipsHmacRunTests(void);

#else // SSI_SUPPORT_FIPS
// empty macro since FIPS not supported
#define CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR()
#define CHECK_AND_RETURN_UPON_FIPS_ERROR()
#define CHECK_AND_RETURN_UPON_FIPS_STATE()
#define CHECK_FIPS_SUPPORTED(supported) \
    {                                   \
        supported = false;              \
    }
#define FIPS_RSA_VALIDATE(pRndContext, pCcUserPrivKey, pCcUserPubKey, pFipsCtx) (SASI_OK)
#define FIPS_ECC_VALIDATE(pRndContext, pUserPrivKey, pUserPublKey, pFipsCtx)    (SASI_UNUSED_PARAM(pRndContext), SASI_OK)
#define SaSi_FIPS_SET_RND_CONT_ERR()

#endif // SSI_SUPPORT_FIPS
#endif // _SaSi_FIPS_DEFS_H
