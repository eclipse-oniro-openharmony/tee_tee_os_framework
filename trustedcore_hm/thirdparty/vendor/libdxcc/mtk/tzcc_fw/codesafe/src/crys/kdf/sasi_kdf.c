/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "ssi_pal_mem.h"
#include "sasi_common_math.h"
#include "sasi_hash.h"
#include "sasi_kdf.h"
#include "sasi_kdf_error.h"
#include "sasi_fips_defs.h"

/* *********************** Defines ***************************** */

/* canceling the lint warning:
   Use of goto is deprecated */


/* *********************** Enums ******************************* */

/* *********************** macros ****************************** */

/* ***********************    Global Data    **************************** */

/* *********************** Private Functions **************************** */

/* ***********************************************************************
 *   The function performs  Hash update for data with the size not
 *   aligned to Hash block.
 *
 *   Note: remBuffSize_ptr - a pointer to the remaining size of the
 *         temp buffer to fill by the data.
 *
 * ********************************************************************* */

/*
 *   The function performs  Hash update for data with the size not
 *   aligned to Hash block.
 *
 *   Note: remBuffSize_ptr - a pointer to the remaining size of the
 *         temp buffer to fill by the data.
 *
 * @author reuvenl (4/3/2013)
 *
 * @param hashContext_ptr - HASH context pointer
 * @param data_ptr        - input data pointer
 * @param dataSize        - input data size in bytes
 * @param buff_ptr        - buffer for remaining data accumulation
 * @param remBuffSize_ptr - size of data on the buffer
 * @param blockSizeBytes  - size of HASH input block in bytes according to mode.
 *
 * @return SaSiError_t
 */
static SaSiError_t SaSi_KdfHashUnalignUpdate(SaSi_HASHUserContext_t *hashContext_ptr, uint8_t *data_ptr,
                                             uint32_t dataSize, uint8_t *buff_ptr, uint32_t *remBuffSize_ptr,
                                             uint32_t blockSizeBytes)
{
    SaSiError_t error = SaSi_OK;
    uint32_t tmpSize;
    uint8_t *tmp_ptr;

    /* set buff_ptr to begin of empty part of temp buffer */
    tmp_ptr = buff_ptr + *remBuffSize_ptr;

    /* if the temp buffer not empty, append it by the data and update Hash on it */
    if (dataSize >= blockSizeBytes - *remBuffSize_ptr) {
        SaSi_PalMemCopy(tmp_ptr, data_ptr, blockSizeBytes - *remBuffSize_ptr);

        /* update on the data in temp buffer */
        error = SaSi_HASH_Update_MTK(hashContext_ptr, buff_ptr, blockSizeBytes);
        if (error != SaSi_OK)
            return error;

        /* update pointers and sizes */
        data_ptr += blockSizeBytes - *remBuffSize_ptr;
        dataSize -= blockSizeBytes - *remBuffSize_ptr;
        *remBuffSize_ptr = 0;
        tmp_ptr          = buff_ptr;
    } else {
        SaSi_PalMemCopy(tmp_ptr, data_ptr, dataSize);
        *remBuffSize_ptr += dataSize;
        return error;
    }

    /* Update Hash on remaining input data */
    tmpSize = dataSize % blockSizeBytes;
    if (tmpSize > 0) {
        dataSize -= tmpSize;
        SaSi_PalMemCopy(tmp_ptr, data_ptr + dataSize, tmpSize);
        *remBuffSize_ptr += tmpSize;
    }

    if (dataSize > 0) {
        error = SaSi_HASH_Update_MTK(hashContext_ptr, data_ptr, dataSize);
    }

    return error;
}

/* *********************** Public Functions **************************** */

/* *********************** Public Functions **************************** */

/* ************************************************************* */
/*
 * @brief SaSi_KDF_KeyDerivFunc_MTK performs key derivation according to one of some modes defined in standards:
        ANSI X9.42-2001, ANSI X9.63, ISO/IEC 18033-2.

    The present implementation of the function allows the following operation modes:
    - SaSi_KDF_ASN1_DerivMode - mode based on  ASN.1 DER encoding;
    - SaSi_KDF_ConcatDerivMode - mode based on concatenation;
    - SaSi_KDF_X963_DerivMode = SaSi_KDF_ConcatDerivMode;
    - SaSi_KDF_ISO18033_KDF1_DerivMode - specific mode according to
        ECIES-KEM algorithm (ISO/IEC 18033-2).

    The purpose of this function is to derive a keying data from the shared secret value and some
    other optional shared information (SharedInfo).

    For calling the API on some specific modes may be used also the following macros:
    - SaSi_KDF_ASN1_KeyDerivFunc;
    - SaSi_KDF_ConcatKeyDerivFunc;

  \note The length in Bytes of the hash result buffer is denoted by "hashlen".
  \note All buffers arguments are represented in Big-Endian format.

  @param[in] ZZSecret_ptr - A pointer to shared secret value octet string.
  @param[in] ZZSecretSize - The size of the shared secret value in bytes. The maximal
        size is defined as: SaSi_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE.
  @param[in] OtherInfo - The  pointer to structure , containing the data,
        shared by two entities of agreement and the data sizes.
        This argument is optional for some modes (if it is not needed - set NULL).
        On KDF OMA_DRM and two ISO/IEC 18033-2 modes - set NULL.
        On KDF ASN1 mode the OtherInfo and its AlgorithmID entry are mandatory.
  @param[in] KDFhashMode - The KDF identifier of hash function to be used.
        The hash function output must be at least 160 bits.
  @param[in] derivation_mode - Specifies one of above described derivation modes.
  @param[out] KeyingData_ptr - A pointer to the buffer for derived keying data.
  @param[in] KeyingDataSizeBytes - The size in bytes of the keying data to be derived.
        The maximal size is defined as: SaSi_KDF_MAX_SIZE_OF_KEYING_DATA.

  @return SaSiError_t - On success the value SaSi_OK is returned,
            and on failure an ERROR as defined in SaSi_KDF_error.h:
            SaSi_KDF_INVALID_ARGUMENT_POINTER_ERROR
            SaSi_KDF_INVALID_KEY_DERIVATION_MODE_ERROR
            SaSi_KDF_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR
            SaSi_KDF_INVALID_SIZE_OF_DATA_TO_HASHING_ERROR
            SaSi_KDF_INVALID_ARGUMENT_HASH_MODE_ERROR
            SaSi_KDF_INVALID_OTHER_INFO_SIZE_ERROR
            SaSi_KDF_INVALID_KEYING_DATA_SIZE_ERROR
*/
CEXPORT_C SaSiError_t SaSi_KDF_KeyDerivFunc_MTK(uint8_t *ZZSecret_ptr, uint32_t ZZSecretSize,
                                                SaSi_KDF_OtherInfo_t *OtherInfo_ptr, SaSi_KDF_HASH_OpMode_t KDFhashMode,
                                                SaSi_KDF_DerivFuncMode_t derivation_mode, uint8_t *KeyingData_ptr,
                                                uint32_t KeyingDataSizeBytes)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;
    /* HASH function context structure buffer and parameters  */
    SaSi_HASHUserContext_t HashContext;
    SaSi_HASH_OperationMode_t hashMode;
    uint32_t HashOutputSizeBytes;

    /* The result buffer for the Hash */
    SaSi_HASH_Result_t HashResultBuff;
    /* Total count of full HASH blockss for deriving the keying data */
    uint32_t CountOfHashBlocks;

    /* Loop counters */
    uint32_t i, j;
    /* counter of Hash blocks (to be hashed with ZZ and OtherInfo) */
    uint32_t Counter;
    /* Current output buffer position */
    uint32_t CurrentOutputBuffPos = 0;

    uint32_t *OtherInfoEntry_ptr;
    uint8_t *temp_ptr;
    uint32_t remBuffSize, blockSizeBytes;
    uint32_t kdfHashTempBuff[SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES / 4];

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ZZSecret_ptr == NULL || KeyingData_ptr == NULL) {
        return SaSi_KDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    if (derivation_mode >= SaSi_KDF_DerivFunc_NumOfModes) {
        return SaSi_KDF_INVALID_KEY_DERIVATION_MODE_ERROR;
    }

    if (derivation_mode == SaSi_KDF_ASN1_DerivMode &&
        (OtherInfo_ptr == NULL || OtherInfo_ptr->SizeOfAlgorithmID == 0)) {
        return SaSi_KDF_INVALID_ARGUMENT_POINTER_ERROR;
    }

    /* On KDF1 and KDF2 derivation modes set OtherInfo_ptr = NULL */
    if (derivation_mode == SaSi_KDF_ISO18033_KDF1_DerivMode || derivation_mode == SaSi_KDF_ISO18033_KDF2_DerivMode) {
        OtherInfo_ptr = NULL;
    }

    /* Check sizes of the input data to be hashed according to KDF        *
     *  limitations)                               */
    if (ZZSecretSize == 0 || ZZSecretSize > SaSi_KDF_MAX_SIZE_OF_SHARED_SECRET_VALUE) {
        return SaSi_KDF_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR;
    }

    if (OtherInfo_ptr != NULL) {
        if ((OtherInfo_ptr->SizeOfAlgorithmID > SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY) ||
            (OtherInfo_ptr->SizeOfPartyUInfo > SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY) ||
            (OtherInfo_ptr->SizeOfPartyVInfo > SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY) ||
            (OtherInfo_ptr->SizeOfSuppPrivInfo > SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY) ||
            (OtherInfo_ptr->SizeOfSuppPubInfo > SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY)) {
            return SaSi_KDF_INVALID_OTHER_INFO_SIZE_ERROR;
        }
    }

    /* Check the size of keying data output. Note: because max size is
       limited in our implementation by SaSi_KDF_MAX_SIZE_OF_KEYING_DATA
       bytes */
    if (KeyingDataSizeBytes == 0 || KeyingDataSizeBytes > SaSi_KDF_MAX_SIZE_OF_KEYING_DATA) {
        return SaSi_KDF_INVALID_KEYING_DATA_SIZE_ERROR;
    }

    /* ................ Setting parameters according to current operation modes .......... */
    /* ------------------------------------------------------------------------------------ */
    blockSizeBytes = SaSi_HASH_BLOCK_SIZE_IN_BYTES; /* for all modes, besides SHA512 */
    switch (KDFhashMode) {
    case SaSi_KDF_HASH_SHA1_mode:
        hashMode            = SaSi_HASH_SHA1_mode;
        HashOutputSizeBytes = SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
        break;
    case SaSi_KDF_HASH_SHA224_mode:
        hashMode            = SaSi_HASH_SHA224_mode;
        HashOutputSizeBytes = SaSi_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
        break;
    case SaSi_KDF_HASH_SHA256_mode:
        hashMode            = SaSi_HASH_SHA256_mode;
        HashOutputSizeBytes = SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
        break;

    case SaSi_KDF_HASH_SHA384_mode:
        hashMode            = SaSi_HASH_SHA384_mode;
        HashOutputSizeBytes = SaSi_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
        blockSizeBytes      = SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;
    case SaSi_KDF_HASH_SHA512_mode:
        hashMode            = SaSi_HASH_SHA512_mode;
        HashOutputSizeBytes = SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
        blockSizeBytes      = SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;

    default:
        return SaSi_KDF_INVALID_ARGUMENT_HASH_MODE_ERROR;
    }

    /* Count of HASH blocks and temp buffer pointer and size */
    CountOfHashBlocks = (KeyingDataSizeBytes + HashOutputSizeBytes - 1) / HashOutputSizeBytes;
    temp_ptr          = (uint8_t *)&kdfHashTempBuff[0];

    /* **********  Keying data derivation loop ************ */

    for (i = 0; i < CountOfHashBlocks; i++) {
        remBuffSize = 0;

        /* .... HASH Init function ..... */
        Error = SaSi_HASH_Init_MTK(&HashContext, hashMode);
        if (Error != SaSi_OK)
            goto End;

        /* ....... Hashing input data by calling HASH_Update function ....... */
        /* ------------------------------------------------------------------ */

        /* .... Hashing of the shared secret value .... */
        Error =
            SaSi_KdfHashUnalignUpdate(&HashContext, ZZSecret_ptr, ZZSecretSize, temp_ptr, &remBuffSize, blockSizeBytes);
        if (Error != SaSi_OK)
            goto End;

        /* .... Hashing of the AlgorithmID (on ASN1 Derivation Mode only) .... */
        if (derivation_mode == SaSi_KDF_ASN1_DerivMode) {
            Error = SaSi_KdfHashUnalignUpdate(&HashContext, (uint8_t *)(OtherInfo_ptr->AlgorithmID),
                                              OtherInfo_ptr->SizeOfAlgorithmID, temp_ptr, &remBuffSize, blockSizeBytes);
            if (Error != SaSi_OK)
                goto End;
        }

        /* Set the blocks counter in big endianness mode */
        if (derivation_mode == SaSi_KDF_ISO18033_KDF1_DerivMode)
            Counter = i;
        else
            Counter = i + 1;

#ifndef BIG__ENDIAN
        Counter = SaSi_COMMON_REVERSE32(Counter);
#endif

        /* .... Hashing of the blocks counter .... */
        Error = SaSi_KdfHashUnalignUpdate(&HashContext, (uint8_t *)&Counter, sizeof(uint32_t), temp_ptr, &remBuffSize,
                                          blockSizeBytes);
        if (Error != SaSi_OK)
            goto End;

        /* ..... Hashing of remaining data of the OtherInfo ..... */
        if (OtherInfo_ptr != NULL) {
            /* Set OtherInfoEntry_ptr to second entry pointer */
            OtherInfoEntry_ptr = (uint32_t *)OtherInfo_ptr + SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY / 4 + 1;

            /* OtherInfo data concatenating and hashing loop */
            for (j = 0; j < SaSi_KDF_COUNT_OF_OTHER_INFO_ENTRIES - 1; j++) {
                /* if entry exists hash it */
                if (*(OtherInfoEntry_ptr + SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY / 4) != 0) {
                    Error = SaSi_KdfHashUnalignUpdate(
                        &HashContext, (uint8_t *)OtherInfoEntry_ptr /* pointer to entry */,
                        *(OtherInfoEntry_ptr + SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY / 4) /* size of entry */, temp_ptr,
                        &remBuffSize, blockSizeBytes);
                    if (Error != SaSi_OK)
                        goto End;
                }
                /* Shift the pointer to the next entry */
                OtherInfoEntry_ptr += SaSi_KDF_MAX_SIZE_OF_OTHER_INFO_ENTRY / 4 + 1;
            }
        }

        /* last Hash update on remaining data in the temp buffer */
        if (remBuffSize > 0) {
            Error = SaSi_HASH_Update_MTK(&HashContext, temp_ptr, remBuffSize);
            if (Error != SaSi_OK)
                goto End;
        }

        /* ..........  HASH Finish operation ............. */
        Error = SaSi_HASH_Finish_MTK(&HashContext, HashResultBuff);
        if (Error != SaSi_OK)
            goto End;

        /* Correction of output data size for last block ( if it is not full ) */
        if (i == (CountOfHashBlocks - 1))
            HashOutputSizeBytes = KeyingDataSizeBytes - i * HashOutputSizeBytes;

        /* Copying HASH data into output buffer */
        SaSi_PalMemCopy(&KeyingData_ptr[CurrentOutputBuffPos], (uint8_t *)HashResultBuff, HashOutputSizeBytes);

        /* Increment the output buffer position */
        CurrentOutputBuffPos += HashOutputSizeBytes;
    }

End:
    /* clean temp buffers */
    SaSi_PalMemSetZero(&HashResultBuff, sizeof(SaSi_HASH_Result_t));
    SaSi_PalMemSetZero(&kdfHashTempBuff, sizeof(kdfHashTempBuff));

    return Error;

} /* END OF SaSi_KDF_KeyDerivationFunc */
