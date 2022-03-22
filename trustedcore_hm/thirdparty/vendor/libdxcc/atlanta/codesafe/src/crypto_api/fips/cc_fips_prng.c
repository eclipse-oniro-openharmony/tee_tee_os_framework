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

#include "cc_pal_log.h"
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_rnd.h"
#include "cc_fips.h"
#include "cc_fips_error.h"
#include "cc_fips_defs.h"
#include "cc_fips_prng_kat_data.h"
/* +++hisilicon */
#include "cc_ctr_drbg.h"
/* ---hisilicon */

typedef struct prngKatData{
        const uint8_t   *pEntropy;
        uint32_t        entropySize;
        const uint8_t   *pNonce;
        uint32_t        nonceSize;
        const uint8_t   *pPersonalStr;
        uint32_t        personalStrSize;
        const uint8_t   *pEntropyInPR1;
        uint32_t        entropyInPR1Size;
        const uint8_t   *pEntropyInPR2;
        uint32_t        entropyInPR2Size;
        const uint8_t   *pAddInput1;
        uint32_t        addInput1Size;
        const uint8_t   *pAddInput2;
        uint32_t        addInput2Size;
        const uint8_t   *pExpectedVector;
        uint32_t        expectedVectorSize;
}PrngKatData_t;

static const PrngKatData_t   prngTestVector[] = {
// No additional data
{ fipsPrng256NoAddEntropyInput, sizeof(fipsPrng256NoAddEntropyInput),
  fipsPrng256NoAddNonce, sizeof(fipsPrng256NoAddNonce),
  fipsPrng256NoAddPersonalStr, sizeof(fipsPrng256NoAddPersonalStr),
  fipsPrng256NoAddEntropyInPR1, sizeof(fipsPrng256NoAddEntropyInPR1),
  fipsPrng256NoAddEntropyInPR2, sizeof(fipsPrng256NoAddEntropyInPR2),
  NULL, 0,
  NULL, 0,
  fipsPrng256NoAddExpVector, sizeof(fipsPrng256NoAddExpVector) },
// with additional data
{ fipsPrng256WithAddEntropyInput, sizeof(fipsPrng256WithAddEntropyInput),
  fipsPrng256WithAddNonce, sizeof(fipsPrng256WithAddNonce),
  fipsPrng256WithAddPersonalStr, sizeof(fipsPrng256WithAddPersonalStr),
  fipsPrng256WithAddEntropyInPR1, sizeof(fipsPrng256WithAddEntropyInPR1),
  fipsPrng256WithAddEntropyInPR2, sizeof(fipsPrng256WithAddEntropyInPR2),
  fipsPrng256WithAddAdditionalInput1, sizeof(fipsPrng256WithAddAdditionalInput1),
  fipsPrng256WithAddAdditionalInput2, sizeof(fipsPrng256WithAddAdditionalInput2),
  fipsPrng256WithAddExpVector, sizeof(fipsPrng256WithAddExpVector) },
};

#define FIPS_PRNG_NUM_OF_TESTS        (sizeof(prngTestVector) / sizeof(PrngKatData_t))

/* KAT test for PRNG.  */
static uint32_t FipsPrngKatInstantiateReseed(CCRndContext_t         *pRndContext, bool isInstantiate,
                                                uint8_t   *pEntropy, uint32_t   entropySize,
                                                uint8_t   *pNonce, uint32_t   nonceSize,
                                                uint8_t   *pAddData, uint32_t   addDataSize,
                                                CCRndWorkBuff_t     *pRndWorkBuff)
{
        uint32_t  rc = CC_OK;

        // enter KAT mode
        rc = CC_RndEnterKatMode(pRndContext,
                                   pEntropy, entropySize,
                                   pNonce, nonceSize,
                                   pRndWorkBuff);
        if (rc != CC_OK) {
                return rc;
        }

        // First instantiate
        rc = CC_RndAddAdditionalInput(pRndContext, pAddData, addDataSize);
        if (rc != CC_OK) {
                return rc;
        }
        if (isInstantiate == true) {
                rc = CC_RndInstantiation(pRndContext, pRndWorkBuff);
        } else {
                rc = CC_RndReseeding(pRndContext, pRndWorkBuff);
        }
        if (rc != CC_OK) {
                return rc;
        }
        return rc;
}

/* KAT test for PRNG.  */
static uint32_t FipsPrngKatSingleTest(CCRndContext_t     *pRndContext,
                                  CCPrngFipsKatCtx_t  *pPrngCtx,
                                   uint32_t              testNum)
{
        uint32_t  rc = CC_OK;
        CCRndWorkBuff_t     *pRndWorkBuff = &pPrngCtx->rndWorkBuff;
        CCRndState_t        *pRndState = &pRndContext->rndState;
        uint8_t                 *pOutputBuff = pPrngCtx->rndOutputBuff;
        PrngKatData_t           *pPrngTestVect = (PrngKatData_t *)&prngTestVector[testNum];


        // initialization
        rc = FipsPrngKatInstantiateReseed(pRndContext, true,
                (uint8_t *)pPrngTestVect->pEntropy, pPrngTestVect->entropySize,
                (uint8_t *)pPrngTestVect->pNonce, pPrngTestVect->nonceSize,
                (uint8_t *)pPrngTestVect->pPersonalStr, pPrngTestVect->personalStrSize,
                pRndWorkBuff);
        if (rc != CC_OK) {
                goto End;
        }

        /* First Reseeding*/
        rc = FipsPrngKatInstantiateReseed(pRndContext, false,
                (uint8_t *)pPrngTestVect->pEntropyInPR1, pPrngTestVect->entropyInPR1Size,
                NULL, 0,
                (uint8_t *)pPrngTestVect->pAddInput1, pPrngTestVect->addInput1Size,
                pRndWorkBuff);
        if (rc != CC_OK) {
                goto End;
        }

        rc = CC_RndGenerateVector(pRndState,
                                     sizeof(pPrngCtx->rndOutputBuff),
                                     pOutputBuff);
        if (rc != CC_OK) {
                goto End;
        }


        /* Second Reseeding*/
        rc = FipsPrngKatInstantiateReseed(pRndContext, false,
                (uint8_t *)pPrngTestVect->pEntropyInPR2, pPrngTestVect->entropyInPR2Size,
                NULL, 0,
                (uint8_t *)pPrngTestVect->pAddInput2, pPrngTestVect->addInput2Size,
                pRndWorkBuff);
        if (rc != CC_OK) {
                goto End;
        }

        rc = CC_RndGenerateVector(pRndState,
                                     sizeof(pPrngCtx->rndOutputBuff),
                                     pOutputBuff);
        if (rc != CC_OK) {
                goto End;
        }
        rc =  CC_RndAddAdditionalInput(pRndContext,
                                        (uint8_t *)pPrngTestVect->pAddInput2, pPrngTestVect->addInput2Size);
        if (rc != CC_OK) {
                goto End;
        }

        /* Verify generated vector is the same as expected  */
        rc = CC_PalMemCmp(pOutputBuff, (uint8_t *)pPrngTestVect->pExpectedVector, pPrngTestVect->expectedVectorSize);
        if (rc != CC_OK) {
                goto End;
        }

End:
        CC_RndUnInstantiation(pRndContext);

        return rc;

}


/* KAT test for PRNG  */
CCFipsError_t CC_FipsPrngKat(CCRndContext_t *pRndContext, CCPrngFipsKatCtx_t *pPrngCtx)
{
        uint32_t        rc = CC_OK;
        CCFipsError_t  fipsRc = CC_TEE_FIPS_ERROR_OK;
        uint32_t        idx;

        if ((pRndContext == NULL) ||
            (pPrngCtx == NULL)) {
                return CC_TEE_FIPS_ERROR_PRNG_PUT;
        }

        // test generate vector with key size of 256 bit
        for (idx=0; idx < FIPS_PRNG_NUM_OF_TESTS; idx++) {
                rc = FipsPrngKatSingleTest(pRndContext, pPrngCtx, idx);
                if (rc != CC_OK) {
                        goto End;
                }
        }


        FipsSetTrace(CC_FIPS_TRACE_PRNG_PUT);

End:
        CC_PalMemSetZero(pRndContext, sizeof(CCRndContext_t));
        CC_PalMemSetZero(pPrngCtx, sizeof(CCPrngFipsKatCtx_t));
        if (rc != CC_OK) {
                fipsRc = CC_TEE_FIPS_ERROR_PRNG_PUT;
        }
        return fipsRc;
}

/* +++hisilicon */
uint32_t do_prng_test(CCRndContext_t      *pRndContext,
                      CCPrngFipsKatCtx_t  *pPrngCtx,
                      struct cc_drbg_data *prngTestVector)
{
        uint32_t rc = CC_FAIL;

        if (!pRndContext || !pPrngCtx || !prngTestVector)
                return rc;

        CCRndWorkBuff_t *pRndWorkBuff = &pPrngCtx->rndWorkBuff;
        CCRndState_t *pRndState = &pRndContext->rndState;
        uint8_t *pOutputBuff = pPrngCtx->rndOutputBuff;
        struct cc_drbg_data *pPrngTestVect = prngTestVector;

        /* initialization */
        rc = FipsPrngKatInstantiateReseed(pRndContext, true,
                (uint8_t *)pPrngTestVect->pEntropy, pPrngTestVect->entropySize,
                (uint8_t *)pPrngTestVect->pNonce, pPrngTestVect->nonceSize,
                (uint8_t *)pPrngTestVect->pPersonalStr, pPrngTestVect->personalStrSize,
                pRndWorkBuff);
        if (rc != CC_OK)
                goto End;

        /* First Reseeding */
        rc = FipsPrngKatInstantiateReseed(pRndContext, false,
                (uint8_t *)pPrngTestVect->pEntropyInPR1, pPrngTestVect->entropyInPR1Size,
                NULL, 0,
                (uint8_t *)pPrngTestVect->pAddInput1, pPrngTestVect->addInput1Size,
                pRndWorkBuff);
        if (rc != CC_OK)
                goto End;

        rc = CC_RndGenerateVector(pRndState, sizeof(pPrngCtx->rndOutputBuff), pOutputBuff);
        if (rc != CC_OK)
                goto End;

        /* Second Reseeding */
        rc = FipsPrngKatInstantiateReseed(pRndContext, false,
                (uint8_t *)pPrngTestVect->pEntropyInPR2, pPrngTestVect->entropyInPR2Size,
                NULL, 0,
                (uint8_t *)pPrngTestVect->pAddInput2, pPrngTestVect->addInput2Size,
                pRndWorkBuff);
        if (rc != CC_OK)
                goto End;

        rc = CC_RndGenerateVector(pRndState, sizeof(pPrngCtx->rndOutputBuff), pOutputBuff);
        if (rc != CC_OK)
                goto End;
End:
        CC_RndUnInstantiation(pRndContext);

        return rc;
}
/* ---hisilicon */
