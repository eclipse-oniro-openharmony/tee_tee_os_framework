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
#include "sasi_fips_defs.h"
#include "pka_ecc_export.h"

/* *********************** Defines ************************************* */

/* *********************** Enums *************************************** */

/* *********************** Typedefs ************************************ */

/* *********************** Global Data ********************************* */

/* ************ Private function prototype ***************************** */

/* *********************** Public Functions **************************** */

CEXPORT_C SaSiError_t _DX_ECPKI_BuildPublKey_MTK(const SaSi_ECPKI_Domain_t *pDomain,     /* in */
                                                 uint8_t *pPublKeyIn,                    /* in */
                                                 uint32_t publKeySizeInBytes,            /* in */
                                                 EC_PublKeyCheckMode_t checkMode,        /* in */
                                                 SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* out */
                                                 SaSi_ECPKI_BUILD_TempData_t *tempBuff /* in */)

{
    /* FUNCTION DECLARATIONS */

    /* the private key structure pointer */
    struct SaSi_ECPKI_PublKey_t *pPublKey;
    /* EC modulus size in bytes */
    uint32_t modSizeInBytes;
    /* Point control pc pc and pc1 = pc&6 */
    uint32_t pc, pc1;
    /* the err return code identifier */
    SaSiError_t err = SaSi_OK;

    /* FUNCTION LOGIC */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the validity of the User given pointers ......... */
    if (pUserPublKey == NULL)
        return SaSi_ECPKI_BUILD_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR;
    if (pPublKeyIn == NULL)
        return SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_IN_PTR_ERROR;
    if (pDomain == NULL)
        return SaSi_ECPKI_DOMAIN_PTR_ERROR;
    /* check input values */
    if (checkMode >= PublKeyChecingOffMode)
        return SaSi_ECPKI_BUILD_KEY_INVALID_CHECK_MODE_ERROR;
    if ((checkMode != CheckPointersAndSizesOnly) && (tempBuff == NULL))
        return SaSi_ECPKI_BUILD_KEY_INVALID_TEMP_BUFF_PTR_ERROR;

    /* check EC domain parameters sizes */
    if ((pDomain->modSizeInBits > (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 32)) ||
        (pDomain->ordSizeInBits > (pDomain->modSizeInBits + 1))) {
        return SaSi_ECPKI_INVALID_DATA_IN_PASSED_STRUCT_ERROR;
    }

    /* ...... Initializations  ............... */

    pPublKey       = (struct SaSi_ECPKI_PublKey_t *)((void *)pUserPublKey->PublKeyDbBuff);
    modSizeInBytes = CALC_FULL_BYTES(pDomain->modSizeInBits);

    // for fuzz test error
    if ((publKeySizeInBytes != modSizeInBytes + 1) && (publKeySizeInBytes != 2 * modSizeInBytes + 1))
        return SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_SIZE_ERROR;

    /* point control */
    pc = pPublKeyIn[0];
    if (pc >= SaSi_EC_PointCompresOffMode || pc == SaSi_EC_PointContWrong)
        return SaSi_ECPKI_BUILD_KEY_INVALID_COMPRESSION_MODE_ERROR;
    pc1 = pc & 0x6; /* compression. mode */

    /* preliminary check key size */
    if (pc1 == SaSi_EC_PointCompressed) {
        if (publKeySizeInBytes != modSizeInBytes + 1)
            return SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_SIZE_ERROR;
    } else {
        if (publKeySizeInBytes != 2 * modSizeInBytes + 1)
            return SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_SIZE_ERROR;
    }

    /* ...... copy the buffers to the key handle structure ................ */
    /* -------------------------------------------------------------------- */

    /* RL ? clear the public key db */
    SaSi_PalMemSetZero((uint8_t *)pUserPublKey, sizeof(SaSi_ECPKI_UserPublKey_t));

    /* copy public key Xin to X, Yin to Y */
    err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pPublKey->x, sizeof(pPublKey->x), pPublKeyIn + 1, modSizeInBytes);
    if (err != SaSi_OK)
        goto End;

    if (pc1 == SaSi_EC_PointUncompressed || pc1 == SaSi_EC_PointHybrid) {
        /*  PC1 = 4 or PC1 = 6 */
        err = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pPublKey->y, sizeof(pPublKey->y),
                                                          pPublKeyIn + 1 + modSizeInBytes, modSizeInBytes);
        if (err != SaSi_OK)
            goto End;
    }

    /* initialize LLF public key   */
    /* ----------------------------- */
    /* copy EC domain */
    SaSi_PalMemCopy(&pPublKey->domain, pDomain, sizeof(SaSi_ECPKI_Domain_t));

    /* Initialization, partly checking and uncompressing (if needed) of the public key */
    err = LLF_ECPKI_InitPubKey(pPublKey, pc);
    if (err != SaSi_OK)
        goto End;

    /*  additional (full) checking of public key  */
    /* -------------------------------------------- */
    if (checkMode == ECpublKeyFullCheck) {
        err = LLF_ECPKI_FullCheckPublKey(pPublKey, (uint32_t *)tempBuff);
        if (err != SaSi_OK) {
            goto End;
        }
    }

    /* ................ set the private key validation tag ................... */
    pUserPublKey->valid_tag = SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG;

End:
    /* if the created structure is not valid - clear it */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pUserPublKey, sizeof(SaSi_ECPKI_UserPublKey_t));
    }
    if (tempBuff != NULL) {
        SaSi_PalMemSetZero(tempBuff, sizeof(SaSi_ECPKI_BUILD_TempData_t));
    }

    return err;

} /* End of _DX_ECPKI_BuildPublKey_MTK() */

/* **********************************************************************************
 *                     SaSi_ECPKI_ExportPublKey_MTK function                           *
 * ******************************************************************************** */
/*
  @brief The function converts an existed public key into the big endian and outputs it.

                 The function performs the following steps:
                 - checks input parameters,
                 - Converts the X,Y coordinates of public key EC point to big endianness.
                 - Sets the public key as follows:
                          In case "Uncompressed" point:  PubKey = PC||X||Y, PC = 0x4 - single byte;
                          In other cases returns an error.
                 - Exits.

                 NOTE: - At this stage supported only uncompressed point form,
                       - Size of output X and Y coordinates is equal to ModSizeInBytes.

  @param[in]  pUserPublKey -   A pointer to the public key structure initialized by SaSi.
  @param[in]  compression  -   An enumerator parameter, defines point compression.
  @param[out] pExportPublKey - A pointer to the buffer for export the public key bytes
                       array in big endian order of bytes. Size of buffer must be
                       not less than 2*ModSiseInBytes+1 bytes.
  @param[in/out] pPublKeySizeBytes - A pointer to size of the user passed
                       public key buffer (in) and the actual size of exported
                       public key (out).

  @return SaSiError_t - SaSi_OK,
                        SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR
                        SaSi_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_COMPRESSION_MODE_ERROR
                        SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_EXTERN_PUBL_KEY_PTR_ERROR
                        SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_PTR_ERROR
                        SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_ERROR
                        SaSi_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_DOMAIN_ID_ERROR
*/
CEXPORT_C SaSiError_t SaSi_ECPKI_ExportPublKey_MTK(SaSi_ECPKI_UserPublKey_t *pUserPublKey,    /* in */
                                                   SaSi_ECPKI_PointCompression_t compression, /* in */
                                                   uint8_t *pExportPublKey,                   /* in */
                                                   uint32_t *pPublKeySizeBytes /* in/out */)
{
    /* -------------------- FUNCTION DECLARATIONS ------------------------ */

    /* the private key structure pointer */
    struct SaSi_ECPKI_PublKey_t *publKey;

    /* EC modulus size in words and in bytes */
    uint32_t modSizeInBytes, modSizeInWords;
    uint8_t yBit;

    /* the err return code identifier */
    SaSiError_t err = SaSi_OK;

    /* ............. Checking input parameters   .............................. */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pUserPublKey == NULL)
        return SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR;

    if (pExportPublKey == NULL)
        return SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_EXTERN_PUBL_KEY_PTR_ERROR;

    if (pUserPublKey->valid_tag != SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG)
        return SaSi_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_VALIDATION_TAG_ERROR;

    if (pPublKeySizeBytes == 0)
        return SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_PTR_ERROR;

    if (compression == SaSi_EC_PointContWrong || compression >= SaSi_EC_PointCompresOffMode)
        return SaSi_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_COMPRESSION_MODE_ERROR;

    /*   FUNCTION LOGIC  */

    publKey = (struct SaSi_ECPKI_PublKey_t *)((void *)pUserPublKey->PublKeyDbBuff);

    /* EC modulus size */
    modSizeInBytes = CALC_FULL_BYTES(publKey->domain.modSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(publKey->domain.modSizeInBits);

    /* calc. MS Bit of Y */
    yBit = (uint8_t)(publKey->y[0] & 1);

    /* Convert public key to big endianness export form */
    switch (compression) {
    case SaSi_EC_PointCompressed:

        if (*pPublKeySizeBytes < modSizeInBytes + 1)
            return SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_ERROR;

        /* point control byte */
        pExportPublKey[0] = 0x02 | yBit;

        err = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pExportPublKey + 1, 4 * modSizeInWords, publKey->x,
                                                          modSizeInBytes);
        if (err != SaSi_OK) {
            goto End;
        }

        *pPublKeySizeBytes = modSizeInBytes + 1;
        break;

    case SaSi_EC_PointUncompressed:
    case SaSi_EC_PointHybrid:

        if (*pPublKeySizeBytes < 2 * modSizeInBytes + 1)
            return SaSi_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_ERROR;

        /* Point control byte */
        if (compression == SaSi_EC_PointUncompressed)
            pExportPublKey[0] = 0x04;
        else
            pExportPublKey[0] = (0x06 | yBit);

        err = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pExportPublKey + 1, 4 * ((modSizeInBytes + 3) / 4),
                                                          publKey->x, modSizeInBytes);
        if (err != SaSi_OK) {
            goto End;
        }
        err = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pExportPublKey + 1 + modSizeInBytes,
                                                          4 * ((modSizeInBytes + 3) / 4), publKey->y, modSizeInBytes);
        if (err != SaSi_OK) {
            goto End;
        }

        /* Set publKeySizeInBytes */
        *pPublKeySizeBytes = 2 * modSizeInBytes + 1;
        break;

    default:
        return SaSi_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_COMPRESSION_MODE_ERROR;
    }
End:
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pExportPublKey, *pPublKeySizeBytes);
        *pPublKeySizeBytes = 0;
    }
    return err;

} /* End of SaSi_ECPKI_ExportPublKey_MTK */
