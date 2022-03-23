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
#include "sasi_ecpki_types.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_export.h"
#include "pka_ecc_export.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_fips_defs.h"
#include "ssi_ecpki_domains_defs.h"

/* *********************** Defines ************************************* */

/* *********************** Enums *************************************** */

/* *********************** Typedefs ************************************ */

/* *********************** Global Data ********************************* */

extern const getDomainFuncP ecDomainsFuncP[SaSi_ECPKI_DomainID_OffMode];
/* ************ Private function prototype ***************************** */

/* *********************** Public Functions **************************** */

/* *********************************************************************************
 *                SaSi_ECPKI_BuildEcDomain function               *
 * ******************************************************************************* */
/*
 * @brief     The function builds (imports) the ECC Domain structure from EC parameters given
 *            by the user in big endian order of bytes in arrays.<br>
 *
 *            When operating the ECC cryptographic operations this function should be
 *            called the first.
 *
 *            The function performs the following operations:
 *                   - Checks pointers and sizes of of incoming parameters.
 *                   - Converts parameters from big endian bytes arrays into little
 *                     endian words arrays, where most left word is a last significant and
 *                     most left one is a most significant.<br>
 *
 *            Note! Assumed that Domain parameters are cheked by the user and therefore the
 *                  function not performs full parameters validitation.
 *
 * @param pMod -  A pointer to EC modulus.
 * @param pA   -  A pointer to parameter A of elliptic curve. The size
 *                of the buffer must be the same as EC modulus.
 * @param pB   -  A pointer to parameter B of elliptic curve. The size
 *                of the buffer must be the same as EC modulus.
 * @param pOrd - A pointer to order of generator (point G).
 * @param pGx -  A pointer to coordinate X of generator G. The size
 *               of the buffer must be the same as Ec modulus.
 * @param pGy -  A pointer to coordinate Y of generator G. The size
 *               of the buffer must be the same as EC modulus.
 * @param pCofactor -  A pointer to EC cofactor - optional. If the pointer
 *               and the size are set to null, than assumed, that given curve has
 *               cofactor = 1 or cofactor should not be included in the calculations.
 * @param modSizeBytes -  A size of of the EC modulus buffer in bytes.
 *               Note: The sizes of the buffers: pA, pB,
 *                     pGx, pGx are equall to pMod size.
 * @param ordSizeBytes -  A size of of the generator order in bytes.
 * @param cofactorSizeBytes -  A size of cofactor buffer in bytes. According to our
 *                implementation cofactorSizeBytes must be not great, than 4 bytes.
 *              If cofactor = 1, then, the size and the pointer may be set to null.
 * @param securityStrengthBits - Optional security strength level S in bits:
 *           see ANS X9.62-2005 A.3.1.4. If this parameter is equal to 0, then
 *           it is ignored, else the function checks the EC order size. If the order
 *           is less than max(S-1, 160), then the function returns an error.
 * @param pDomain - A pointer to EC domain structure.
 *
 * @return SaSiError_t:
 *                         SaSi_OK
 *                         SaSi_ECPKI_BUILD_DOMAIN_DOMAIN_PTR_ERROR
 *                         SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_PTR_ERROR
 *                         SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR
 *                         SaSi_ECPKI_BUILD_DOMAIN_SECURITY_STRENGTH_ERROR
 */
CEXPORT_C SaSiError_t SaSi_ECPKI_BuildEcDomain(uint8_t *pMod,                 /* in */
                                               uint8_t *pA,                   /* in */
                                               uint8_t *pB,                   /* in */
                                               uint8_t *pOrd,                 /* in */
                                               uint8_t *pGx,                  /* in */
                                               uint8_t *pGy,                  /* in */
                                               uint8_t *pCof,                 /* in */
                                               uint32_t modSizeBytes,         /* in */
                                               uint32_t ordSizeBytes,         /* in */
                                               uint32_t cofSizeBytes,         /* in */
                                               uint32_t securityStrengthBits, /* in */
                                               SaSi_ECPKI_Domain_t *pDomain /* out */)

{
    /* FUNCTION DECLARATIONS */

    SaSiError_t err = SaSi_OK;
    uint32_t modSizeBits, modSizeWords, ordSizeBits, ordSizeWords;

    /* FUNCTION LOGIC */

    /* check input pointers */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pDomain == NULL)
        return SaSi_ECPKI_BUILD_DOMAIN_DOMAIN_PTR_ERROR;

    if (pMod == NULL || pA == NULL || pB == NULL || pOrd == NULL || pGx == NULL || pGy == NULL)
        return SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_PTR_ERROR;

    /* check the sizes */

    if (modSizeBytes == 0 || ordSizeBytes == 0)
        return SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;

    if (modSizeBytes > SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * sizeof(uint32_t))
        return SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;

    if (pCof == NULL && cofSizeBytes != 0)
        return SaSi_ECPKI_BUILD_DOMAIN_COFACTOR_PARAMS_ERROR;

    if (cofSizeBytes > sizeof(uint32_t)) /* according to our implementation */
        return SaSi_ECPKI_BUILD_DOMAIN_COFACTOR_PARAMS_ERROR;

    /* clean domain structure */
    SaSi_PalMemSetZero(pDomain, sizeof(SaSi_ECPKI_Domain_t));

    /* convert the data to words arrays with little endian order of words,
       calculate and check exact bit - sizes */

    /* EC modulus */
    modSizeWords = CALC_32BIT_WORDS_FROM_BYTES(modSizeBytes);
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecP, ROUNDUP_BYTES_TO_32BIT_WORD(modSizeBytes), pMod,
                                                      modSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* correction of mod. size */
    modSizeBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pDomain->ecP, modSizeWords);

    modSizeBytes = CALC_FULL_BYTES(modSizeBits);
    modSizeWords = CALC_FULL_32BIT_WORDS(modSizeBits);
    /* check mod size to prevent KW warnings */
    if (modSizeWords > SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS) {
        err = SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;
        goto End;
    }

    pDomain->modSizeInBits = modSizeBits;

    /* Ec order */
    ordSizeWords = CALC_32BIT_WORDS_FROM_BYTES(ordSizeBytes);
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecR, ROUNDUP_BYTES_TO_32BIT_WORD(ordSizeBytes), pOrd,
                                                      ordSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* correction of order size */
    ordSizeBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pDomain->ecR, ordSizeWords);
    /* according to EC curves features */
    if (ordSizeBits > modSizeBits + 1) {
        err = SaSi_ECPKI_BUILD_DOMAIN_EC_PARAMETR_SIZE_ERROR;
        goto End;
    }

    pDomain->ordSizeInBits = ordSizeBits;

    /* check curve security strength, if it is given > 0 */
    if (securityStrengthBits > 0 && ordSizeBits < SaSi_MAX(2 * securityStrengthBits - 1, 160)) {
        err = SaSi_ECPKI_BUILD_DOMAIN_SECURITY_STRENGTH_ERROR;
        goto End;
    }

    /* A - parameter */
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecA, sizeof(uint32_t) * modSizeWords, pA, modSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* B - parameter */
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecB, sizeof(uint32_t) * modSizeWords, pB, modSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* Gx */
    err =
        SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecGx, sizeof(uint32_t) * modSizeWords, pGx, modSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* Gy */
    err =
        SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pDomain->ecGy, sizeof(uint32_t) * modSizeWords, pGy, modSizeBytes);
    if (err != SaSi_OK) {
        goto End;
    }

    /* Cofactor */
    if (cofSizeBytes > 0) {
        err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(&pDomain->ecH, ROUNDUP_BYTES_TO_32BIT_WORD(cofSizeBytes),
                                                          pCof, cofSizeBytes);
        if (err != SaSi_OK) {
            goto End;
        }
    } else {
        pDomain->ecH = 1;
    }

    /* Calculate Barrett tags for modulus and order */

    err = PKA_CalcNp(&pDomain->llfBuff[0], pDomain->ecP, modSizeBits);
    if (err != SaSi_OK) {
        goto End;
    }

    err = PKA_CalcNp(&pDomain->llfBuff[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS], pDomain->ecR, ordSizeBits);
    if (err != SaSi_OK) {
        goto End;
    }

    pDomain->barrTagSizeInWords = SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS;

    /* set Domain ID to unknown (builded) mode */
    pDomain->DomainID = SaSi_ECPKI_DomainID_Builded;
End:
    if (err != SaSi_OK) {
        /* clean domain structure */
        SaSi_PalMemSetZero(pDomain, sizeof(SaSi_ECPKI_Domain_t));
    }
    return err;

} /* End SaSi_ECPKI_BuildEcDomain */

/*
 @brief    the function returns the domain pointer
 @return   return domain pointer

*/
const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetEcDomain(SaSi_ECPKI_DomainID_t domainId)
{
    if (domainId >= SaSi_ECPKI_DomainID_OffMode) {
        return NULL;
    }

    if (ecDomainsFuncP[domainId] == NULL) {
        return NULL;
    }

    return ((ecDomainsFuncP[domainId])());
}
