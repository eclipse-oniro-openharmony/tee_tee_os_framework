/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */

#include "ssi_pal_mem.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_export.h"
#include "pka_ecc_export.h"

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs *************************** */

/* *********************** Global Data ************************ */

/* ************ Private function prototype ******************** */

/* *********************** Public Functions ******************* */

/* **************  LLF_ECPKI_GenKeyPair function  ************ */
/*
 @brief Generates a pair of private and public keys
        in little endian ordinary (non-Montgomery) form.

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

 @return <b>SaSiError_t</b>: <br>
                       SaSi_OK<br>
                        SaSi_ECPKI_DOMAIN_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
                        SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
*/
CEXPORT_C SaSiError_t LLF_ECPKI_GenKeyPair(const SaSi_ECPKI_Domain_t *pDomain,     /* in */
                                           SaSi_ECPKI_UserPrivKey_t *pUserPrivKey, /* out */
                                           SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* out */
                                           SaSi_ECPKI_KG_TempData_t *pTempBuff)    /* in */
{
    SaSiError_t err = SaSi_OK;
    SaSi_ECPKI_PrivKey_t *pPrivKey;
    struct SaSi_ECPKI_PublKey_t *pPublKey;
    uint32_t orderSizeInWords;

    /* ......... checking the validity of arguments .......... */
    /* ------------------------------------------------------- */

    if (pDomain == NULL)
        return SaSi_ECPKI_DOMAIN_PTR_ERROR;

    if (pUserPrivKey == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR;

    if (pUserPublKey == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR;

    if (pTempBuff == NULL)
        return SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;

    /* the pointer to the key database */
    pPrivKey = (SaSi_ECPKI_PrivKey_t *)&pUserPrivKey->PrivKeyDbBuff;
    pPublKey = (struct SaSi_ECPKI_PublKey_t *)&pUserPublKey->PublKeyDbBuff;

    orderSizeInWords = (pDomain->ordSizeInBits + SASI_BITS_IN_32BIT_WORD - 1) / SASI_BITS_IN_32BIT_WORD;

    /* calculate public key point coordinates */
    err = LLF_ECPKI_ScalarMult(pDomain, pPrivKey->PrivKey /* scalar */, orderSizeInWords, /* scalar size */
                               (uint32_t *)&pDomain->ecGx, (uint32_t *)&pDomain->ecGy,  /* in point coordinates */
                               pPublKey->x, pPublKey->y,                                /* out point coordinates */
                               (uint32_t *)pTempBuff);
    if (err)
        goto End;

    if (err == SASI_OK) {
        /*     set the EC domain and  keys valid tags        */
        SaSi_PalMemCopy((uint8_t *)&pPrivKey->domain, (uint8_t *)pDomain, sizeof(pPrivKey->domain));
        pUserPrivKey->valid_tag = SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG;

        SaSi_PalMemCopy((uint8_t *)&pPublKey->domain, (uint8_t *)pDomain, sizeof(pPublKey->domain));
        pUserPublKey->valid_tag = SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG;
        return err;
    }

End:
    pUserPrivKey->valid_tag = 0;
    pUserPublKey->valid_tag = 0;
    SaSi_PalMemSet(pPrivKey, 0, sizeof(pPrivKey->PrivKey));
    SaSi_PalMemSet(pPublKey, 0, 2 * sizeof(pPublKey->x));
    return err;

} /* END OF LLF_ECPKI_GenKeyPair */

/* ******************************************************************* */
