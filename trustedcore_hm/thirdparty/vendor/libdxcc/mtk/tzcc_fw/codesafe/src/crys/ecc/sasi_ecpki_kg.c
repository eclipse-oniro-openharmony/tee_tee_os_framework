/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_mem.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_export.h"
#include "pka_ecc_export.h"
#include "ssi_general_defs.h"
#include "sasi_fips_defs.h"

/* **************  SaSi_ECPKI_GenKeyPair_MTK function  ************ */
/*
 @brief Generates a pair of private and public keys in little endian ordinary form according to [ANS X9.31].

    The function performs the following:
      1. Checks the validity of all of the function inputs. If one of the received
         parameters is not valid, it returns an error.
      2. Cleans buffers and generates random private key.
      3. Calls the low level function LLF_ECPKI_ScalarMult to generate EC public key.
      4. Outputs the user public and private key structures in little endian form.
      5. Cleans temporary buffers.
      6. Exits.

 @param [in/out] pRndContext - The pointer to random context (state).
 @param [in] pDomain  - The pointer to current EC domain.
 @param [in/out] pRndContext - The pointer to random context (state).
 @param [out] pUserPrivKey - The pointer to the private key structure.
 @param [out] pUserPublKey - The pointer to the public key structure.
 @param [in] pTempBuf - Temporary buffers of size, defined by SaSi_ECPKI_KG_TempData_t.
 @param [in] pFipsCtx - Pointer to temporary buffer used in case FIPS certification if required

 @return <b>SaSiError_t</b>: <br>
                       SaSi_OK<br>
                        SaSi_ECPKI_RND_CONTEXT_PTR_ERROR
                        SaSi_ECPKI_DOMAIN_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
*/
CEXPORT_C SaSiError_t SaSi_ECPKI_GenKeyPair_MTK(SaSi_RND_Context_t *pRndContext,        /* in/out */
                                                const SaSi_ECPKI_Domain_t *pDomain,     /* in */
                                                SaSi_ECPKI_UserPrivKey_t *pUserPrivKey, /* out */
                                                SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* out */
                                                SaSi_ECPKI_KG_TempData_t *pTempBuff,    /* in */
                                                SaSi_ECPKI_KG_FipsContext_t *pFipsCtx)  /* in */
{
    SaSiError_t err = SaSi_OK;
    SaSi_ECPKI_PrivKey_t *pPrivKey;
    uint32_t orderSizeInWords;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ......... checking the validity of arguments .......... */
    /* ------------------------------------------------------- */

    if (pRndContext == NULL)
        return SaSi_ECPKI_RND_CONTEXT_PTR_ERROR;

    if (pDomain == NULL)
        return SaSi_ECPKI_DOMAIN_PTR_ERROR;

    if (pUserPrivKey == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR;

    if (pUserPublKey == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR;

    if (pTempBuff == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;

    /* .........  clear all input structures  ............ */

    SaSi_PalMemSetZero(pUserPrivKey, sizeof(SaSi_ECPKI_UserPrivKey_t));
    SaSi_PalMemSetZero(pUserPublKey, sizeof(SaSi_ECPKI_UserPublKey_t));

    /* the pointer to the key database */
    pPrivKey = (SaSi_ECPKI_PrivKey_t *)&pUserPrivKey->PrivKeyDbBuff;

    orderSizeInWords = (pDomain->ordSizeInBits + SASI_BITS_IN_32BIT_WORD - 1) / SASI_BITS_IN_32BIT_WORD;
    /*  set EC order as max. vect. */
    SaSi_PalMemCopy(pTempBuff, pDomain->ecR, sizeof(uint32_t) * orderSizeInWords);
    /* LR TBD! set right LE bytes order for pTempBuff, when BE PC is used */

    /* generate random private key vector in range: 1 < privKey < EcOrder *
     * Note: we exclude privKey = 1, allowed by FIPS 186-4, because the   *
     *  negligible low probability of its random generation                */
    pPrivKey->PrivKey[orderSizeInWords - 1] = 0;
    err = SaSi_RND_GenerateVectorInRange(pRndContext, (uint32_t)pDomain->ordSizeInBits,
                                         (uint8_t *)pTempBuff /* MaxVect */, (uint8_t *)pPrivKey->PrivKey /* RndVect */);
    if (err) {
        goto End;
    }

    err = LLF_ECPKI_GenKeyPair(pDomain, pUserPrivKey, pUserPublKey, pTempBuff);
    if (err) {
        goto End;
    }
    err = FIPS_ECC_VALIDATE(pRndContext, pUserPrivKey, pUserPublKey, pFipsCtx);
End:
    if (err) {
        SaSi_PalMemSetZero(pUserPrivKey, sizeof(SaSi_ECPKI_UserPrivKey_t));
        SaSi_PalMemSetZero(pUserPublKey, sizeof(SaSi_ECPKI_UserPublKey_t));
    }
    if (pFipsCtx != NULL) {
        SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_ECPKI_KG_FipsContext_t));
    }

    SaSi_PalMemSetZero(pTempBuff, sizeof(SaSi_ECPKI_KG_TempData_t));
    return err;
} /* END OF SaSi_ECPKI_GenKeyPair_MTK */

/* ******************************************************************* */
