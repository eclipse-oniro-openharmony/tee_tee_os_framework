/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_log.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sasi_rnd.h"
#include "sasi_fips.h"
#include "sasi_fips_error.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_prng_kat_data.h"

typedef struct prngKatData {
    const uint8_t *pEntropy;
    uint32_t entropySize;
    const uint8_t *pNonce;
    uint32_t nonceSize;
    const uint8_t *pPersonalStr;
    uint32_t personalStrSize;
    const uint8_t *pEntropyInPR1;
    uint32_t entropyInPR1Size;
    const uint8_t *pEntropyInPR2;
    uint32_t entropyInPR2Size;
    const uint8_t *pAddInput1;
    uint32_t addInput1Size;
    const uint8_t *pAddInput2;
    uint32_t addInput2Size;
    const uint8_t *pExpectedVector;
    uint32_t expectedVectorSize;
} PrngKatData_t;

static const PrngKatData_t prngTestVector[] = {
    // No additional data
    { fipsPrng256NoAddEntropyInput, sizeof(fipsPrng256NoAddEntropyInput), fipsPrng256NoAddNonce,
      sizeof(fipsPrng256NoAddNonce), fipsPrng256NoAddPersonalStr, sizeof(fipsPrng256NoAddPersonalStr),
      fipsPrng256NoAddEntropyInPR1, sizeof(fipsPrng256NoAddEntropyInPR1), fipsPrng256NoAddEntropyInPR2,
      sizeof(fipsPrng256NoAddEntropyInPR2), NULL, 0, NULL, 0, fipsPrng256NoAddExpVector,
      sizeof(fipsPrng256NoAddExpVector) },
    // with additional data
    { fipsPrng256WithAddEntropyInput, sizeof(fipsPrng256WithAddEntropyInput), fipsPrng256WithAddNonce,
      sizeof(fipsPrng256WithAddNonce), fipsPrng256WithAddPersonalStr, sizeof(fipsPrng256WithAddPersonalStr),
      fipsPrng256WithAddEntropyInPR1, sizeof(fipsPrng256WithAddEntropyInPR1), fipsPrng256WithAddEntropyInPR2,
      sizeof(fipsPrng256WithAddEntropyInPR2), fipsPrng256WithAddAdditionalInput1,
      sizeof(fipsPrng256WithAddAdditionalInput1), fipsPrng256WithAddAdditionalInput2,
      sizeof(fipsPrng256WithAddAdditionalInput2), fipsPrng256WithAddExpVector, sizeof(fipsPrng256WithAddExpVector) },
};

#define FIPS_PRNG_NUM_OF_TESTS (sizeof(prngTestVector) / sizeof(PrngKatData_t))

/* KAT test for PRNG.  */
static uint32_t FipsPrngKatInstantiateReseed(SaSi_RND_Context_t *pRndContext, bool isInstantiate, uint8_t *pEntropy,
                                             uint32_t entropySize, uint8_t *pNonce, uint32_t nonceSize,
                                             uint8_t *pAddData, uint32_t addDataSize, SaSi_RND_WorkBuff_t *pRndWorkBuff)
{
    uint32_t rc = SaSi_OK;

    // enter KAT mode
    rc = SaSi_RND_EnterKatMode(pRndContext, pEntropy, entropySize, pNonce, nonceSize, pRndWorkBuff);
    if (rc != SaSi_OK) {
        return rc;
    }

    // First instantiate
    rc = SaSi_RND_AddAdditionalInput(pRndContext, pAddData, addDataSize);
    if (rc != SaSi_OK) {
        return rc;
    }
    if (isInstantiate == true) {
        rc = SaSi_RND_Instantiation(pRndContext, pRndWorkBuff);
    } else {
        rc = SaSi_RND_Reseeding(pRndContext, pRndWorkBuff);
    }
    if (rc != SaSi_OK) {
        return rc;
    }
    return rc;
}

/* KAT test for PRNG.  */
static uint32_t FipsPrngKatSingleTest(SaSi_RND_Context_t *pRndContext, SaSi_PrngFipsKatCtx_t *pPrngCtx,
                                      uint32_t testNum)
{
    uint32_t rc                       = SaSi_OK;
    SaSi_RND_WorkBuff_t *pRndWorkBuff = &pPrngCtx->rndWorkBuff;
    SaSi_RND_State_t *pRndState       = &pRndContext->rndState;
    uint8_t *pOutputBuff              = pPrngCtx->rndOutputBuff;
    PrngKatData_t *pPrngTestVect      = (PrngKatData_t *)&prngTestVector[testNum];

    // initialization
    rc = FipsPrngKatInstantiateReseed(pRndContext, true, (uint8_t *)pPrngTestVect->pEntropy, pPrngTestVect->entropySize,
                                      (uint8_t *)pPrngTestVect->pNonce, pPrngTestVect->nonceSize,
                                      (uint8_t *)pPrngTestVect->pPersonalStr, pPrngTestVect->personalStrSize,
                                      pRndWorkBuff);
    if (rc != SaSi_OK) {
        goto End;
    }

    /* First Reseeding */
    rc = FipsPrngKatInstantiateReseed(pRndContext, false, (uint8_t *)pPrngTestVect->pEntropyInPR1,
                                      pPrngTestVect->entropyInPR1Size, NULL, 0, (uint8_t *)pPrngTestVect->pAddInput1,
                                      pPrngTestVect->addInput1Size, pRndWorkBuff);
    if (rc != SaSi_OK) {
        goto End;
    }

    rc = SaSi_RND_GenerateVector_MTK(pRndState, sizeof(pPrngCtx->rndOutputBuff), pOutputBuff);
    if (rc != SaSi_OK) {
        goto End;
    }

    /* Second Reseeding */
    rc = FipsPrngKatInstantiateReseed(pRndContext, false, (uint8_t *)pPrngTestVect->pEntropyInPR2,
                                      pPrngTestVect->entropyInPR2Size, NULL, 0, (uint8_t *)pPrngTestVect->pAddInput2,
                                      pPrngTestVect->addInput2Size, pRndWorkBuff);
    if (rc != SaSi_OK) {
        goto End;
    }

    rc = SaSi_RND_GenerateVector_MTK(pRndState, sizeof(pPrngCtx->rndOutputBuff), pOutputBuff);
    if (rc != SaSi_OK) {
        goto End;
    }
    rc = SaSi_RND_AddAdditionalInput(pRndContext, (uint8_t *)pPrngTestVect->pAddInput2, pPrngTestVect->addInput2Size);
    if (rc != SaSi_OK) {
        goto End;
    }

    /* Verify generated vector is the same as expected  */
    rc = SaSi_PalMemCmp(pOutputBuff, (uint8_t *)pPrngTestVect->pExpectedVector, pPrngTestVect->expectedVectorSize);
    if (rc != SaSi_OK) {
        goto End;
    }

End:
    SaSi_RND_UnInstantiation(pRndContext);

    return rc;
}

/* KAT test for PRNG  */
CC_FipsError_t SaSi_FipsPrngKat(SaSi_RND_Context_t *pRndContext, SaSi_PrngFipsKatCtx_t *pPrngCtx)
{
    uint32_t rc           = SaSi_OK;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;
    uint32_t idx;

    if ((pRndContext == NULL) || (pPrngCtx == NULL)) {
        return CC_TEE_FIPS_ERROR_PRNG_PUT;
    }

    // test generate vector with key size of 256 bit
    for (idx = 0; idx < FIPS_PRNG_NUM_OF_TESTS; idx++) {
        rc = FipsPrngKatSingleTest(pRndContext, pPrngCtx, idx);
        if (rc != SaSi_OK) {
            goto End;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_PRNG_PUT);

End:
    SaSi_PalMemSetZero(pRndContext, sizeof(SaSi_RND_Context_t));
    SaSi_PalMemSetZero(pPrngCtx, sizeof(SaSi_PrngFipsKatCtx_t));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_PRNG_PUT;
    }
    return fipsRc;
}
