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
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "sasi_fips_defs.h"
#include "pka_ecc_export.h"

/* canceling the lint warning:
   Info 717: do ... while(0) */


/* canceling the lint warning:
   Use of goto is deprecated */


/* canceling the lint warning:
Info 716: while(1) ... */


/* *********************** Defines ************************************* */

/* canceling the lint warning:
   Unusual pointer cast (incompatible indirect types) */


/* *********************** Enums *************************************** */

/* *********************** Typedefs ************************************ */

/* *********************** Global Data ********************************* */

/* ************ Private function prototype ***************************** */

/* *********************** Public Functions **************************** */

/* *********************************************************************************
 *                    SaSi_ECPKI_BuildPrivKey_MTK function                            *
 * ******************************************************************************* */
/*
 * The function checks and imports (builds) private key and EC domain into
 * structure of defined type.
 *
 *  This function should be called before using of the private key. Input
 *  domain structure must be initialized by EC parameters and auxiliary
 *  values, using SaSi_ECPKI_GetDomain or SaSi_ECPKI_SetDomain functions.
 *
 *  The function does the following:
 *      - Checks validity of incoming variables and pointers;
 *      - Converts private key to words arrays with little endian order
 *        of the words and copies it in the UserPrivKey buffer.
 *      - Copies EC domain into UserPrivKey  buffer.
 *
 * @author reuvenl (8/11/2014)
 * @param pDomain - The pointer to EC domain structure.
 * @param pPrivKeyIn - The pointer to private key data.
 * @param PrivKeySizeInBytes - The size of private key data in bytes.
 * @param pUserPrivKey - The pointer to private key structure.
 *
 * @return CEXPORT_C SaSiError_t
 */
CEXPORT_C SaSiError_t SaSi_ECPKI_BuildPrivKey_MTK(const SaSi_ECPKI_Domain_t *pDomain, /* in */
                                                  const uint8_t *pPrivKeyIn,          /* in */
                                                  uint32_t privKeySizeInBytes,        /* in */
                                                  SaSi_ECPKI_UserPrivKey_t *pUserPrivKey /* out */)
{
    /* FUNCTION DECLARATIONS */

    /* the private key structure pointer */
    SaSi_ECPKI_PrivKey_t *pPrivKey;
    /*  EC domain info structure and parameters */
    uint32_t orderSizeInBytes;
    /* the err return code identifier */
    SaSiError_t err = SaSi_OK;

    /* FUNCTION LOGIC */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* checking the validity of arguments */
    if (pPrivKeyIn == NULL)
        return SaSi_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_IN_PTR_ERROR;
    if (pUserPrivKey == NULL)
        return SaSi_ECPKI_BUILD_KEY_INVALID_USER_PRIV_KEY_PTR_ERROR;
    if (pDomain == NULL)
        return SaSi_ECPKI_DOMAIN_PTR_ERROR;

    /* check EC domain parameters sizes */
    if ((pDomain->modSizeInBits > (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 32)) ||
        (pDomain->ordSizeInBits > (pDomain->modSizeInBits + 1))) {
        return SaSi_ECPKI_INVALID_DATA_IN_PASSED_STRUCT_ERROR;
    }

    /* ***************  FUNCTION LOGIC  ************************************ */

    /* the pointer to the key database */
    pPrivKey = (SaSi_ECPKI_PrivKey_t *)((void *)pUserPrivKey->PrivKeyDbBuff);

    /* check key size */
    orderSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    if (privKeySizeInBytes == 0 || privKeySizeInBytes > orderSizeInBytes)
        return SaSi_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_SIZE_ERROR;

    /* loading the private key (little endian) */
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pPrivKey->PrivKey, sizeof(pPrivKey->PrivKey), pPrivKeyIn,
                                                      privKeySizeInBytes);
    if (err != SaSi_OK)
        goto End;

    /* check the value of the private key */
    if (privKeySizeInBytes == orderSizeInBytes) {
        if (SaSi_COMMON_CmpLsWordsUnsignedCounters(
                pPrivKey->PrivKey, (uint16_t)(privKeySizeInBytes + 3) / sizeof(uint32_t), pDomain->ecR,
                (uint16_t)(privKeySizeInBytes + 3) / sizeof(uint32_t)) != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
            err = SaSi_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_DATA_ERROR;
            goto End;
        }
    }

    /* compare to 0 */
    if (SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pPrivKey->PrivKey,
                                                       (privKeySizeInBytes + 3) / sizeof(uint32_t)) == 0) {
        err = SaSi_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_DATA_ERROR;
        goto End;
    }

    /* copy EC domain */
    SaSi_PalMemCopy(&pPrivKey->domain, pDomain, sizeof(SaSi_ECPKI_Domain_t));

    /* ................ set the private key validation tag ................... */
    pUserPrivKey->valid_tag = SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG;

End:
    /* if the created structure is not valid - clear it */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pUserPrivKey, sizeof(SaSi_ECPKI_UserPrivKey_t));
    }

    return err;

} /* End of SaSi_ECPKI_BuildPrivKey_MTK() */
