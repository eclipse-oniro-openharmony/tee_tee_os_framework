/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_ASYM_RSA_DH

/* ************ Include Files ************** */

#include "ssi_pal_mem.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_rsa_error.h"
#include "sasi_rsa_local.h"
#include "llf_rsa.h"
#include "llf_rsa_public.h"
#include "llf_rsa_private.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Public Functions **************************** */

/* ******************************************************************************* */
/*
@brief
SaSi_RSA_PRIM_Encrypt_MTK implements the RSAEP algorithm as defined in PKCS#1 v2.1 6.1.1

  @param[in] UserPubKey_ptr - Pointer to the public key data structure.
  @param[in] PrimeData_ptr - A pointer to a structure containing temp buffers.
  @param[in] Data_ptr - Pointer to the input data to be encrypted.
  @param[in] DataSize - The size, in bytes, of the input data.
            \Note: DataSize <= modulus size is supported, but recommended
            that size is equal to modulus size. If smaller, the data will be
            zero-padded on left side up to the modulus size and therefore,
            after further decrypt operation its result will contain
            padding zeros also.
  @param[out] Output_ptr - Pointer to the encrypted data. The size of output data
            is always equal to size modulus size. The output buffer
            must be at least of modulus size in bytes.

  @return SaSiError_t - SaSi_OK,
            SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
            SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR,
            SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID,
            SaSi_RSA_DATA_POINTER_INVALID_ERROR,
            SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR,
            SaSi_RSA_INVALID_MESSAGE_BUFFER_SIZE,
            SaSi_RSA_INVALID_MESSAGE_DATA_SIZE,
            SaSi_RSA_INVALID_MESSAGE_VAL
 */
CEXPORT_C SaSiError_t SaSi_RSA_PRIM_Encrypt_MTK(SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                                SaSi_RSAPrimeData_t *PrimeData_ptr, uint8_t *Data_ptr,
                                                uint16_t DataSize, uint8_t *Output_ptr)
{
    /* FUNCTION LOCAL DECLERATIONS */

    /* the counter compare result */
    SaSi_COMMON_CmpCounter_t CounterCmpResult;

    /* the public key database pointer */
    SaSiRSAPubKey_t *PubKey_ptr;

    /* the modulus size in bytes */
    uint32_t nSizeInBytes;

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters pointers validity .......... */
    /* -------------------------------------------------------------------- */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();
    /* checking the key database handle pointer */
    if (UserPubKey_ptr == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPubKey_ptr->valid_tag != SaSi_RSA_PUB_KEY_VALIDATION_TAG)
        return SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == NULL)
        return SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* if the users Data pointer is illegal return an error */
    if (Data_ptr == NULL)
        return SaSi_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the users output pointer is illegal return an error */
    if (Output_ptr == NULL)
        return SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;

    /* if the data size is larger then the internal buffer return error */
    if (DataSize > sizeof(PrimeData_ptr->DataIn))
        return SaSi_RSA_INVALID_MESSAGE_BUFFER_SIZE;

    /* setting the pointer to the key database */
    PubKey_ptr = (SaSiRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

    /* setting the modulus size in bytes */
    nSizeInBytes = CALC_FULL_BYTES(PubKey_ptr->nSizeInBits);

    /* ................ copying the input data to the buffer .............. */
    /* -------------------------------------------------------------------- */

    /* clear the input data */
    SaSi_PalMemSet(PrimeData_ptr->DataIn, 0, sizeof(PrimeData_ptr->DataIn));

    /* copy the input data to the aligned buffer on the data handler */
    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrimeData_ptr->DataIn, 4 * ((nSizeInBytes + 3) / 4), Data_ptr,
                                                        DataSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ...... checking the the message value it must be less then the modulus ...... */
    CounterCmpResult = SaSi_COMMON_CmpLsWordsUnsignedCounters(PrimeData_ptr->DataIn, (uint16_t)(nSizeInBytes + 3) / 4,
                                                              PubKey_ptr->n, (uint16_t)(nSizeInBytes + 3) / 4);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_RSA_INVALID_MESSAGE_VAL;
        goto End;
    }

    /* executing the encryption */
    Error = LLF_PKI_RSA_ExecPubKeyExp(PubKey_ptr, PrimeData_ptr);

    if (Error != SaSi_OK) {
        goto End;
    }

    /* copy the output data from the aligned buffer to the users data on big endian format */
    Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(Output_ptr, 4 * ((nSizeInBytes + 3) / 4),
                                                        PrimeData_ptr->DataOut, nSizeInBytes);
    if (Error != SaSi_OK) {
        goto End;
    }

End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Output_ptr, nSizeInBytes);
    }
    /* clear the data buffer */
    SaSi_PalMemSetZero(PrimeData_ptr, sizeof(SaSi_RSAPrimeData_t));

    return Error;

} /* END OF SaSi_RSA_PRIM_Encrypt_MTK */

/* ******************************************************************************* */
/*
@brief
SaSi_RSA_PRIM_Decrypt_MTK implements the RSADP algorithm as defined in PKCS#1 v2.1 6.1.2

  @param[in] PrivKey_ptr - Pointer to the private key data
               structure. \note The RSA key parameters and hence the algorithm (CRT
               or not) are determined by this structure. Using SaSi_Build_PrivKey or
               SaSi_Build_PrivKeyCRT determines which algorithm will be used.

  @param[in] PrimeData_ptr - A pointer to a structure containing internal
                 buffers required for the RSA operation.
  @param[in] Data_ptr - Pointer to the data to be decrypted.
  @param[in] DataSize - The size, in bytes, of the input data. To decrypt
            previously encrypted data its size must be equal to
            modulus size.
            \Note: DataSize <= modulus size is supported, but
            it is recommended that the size is equal to modulus size.
            If smaller, the data will be zero-padded on left side
            up to the modulus size and therefore, after further decrypt
            operation its result will contain padding zeros also.
  @param[out] Output_ptr - Pointer to the decrypted data. The size of output data
            is always equal to size modulus size. The output buffer
            must be at least of modulus size in bytes.

  @return SaSiError_t - SaSi_OK,
            SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
            SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID,
            SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR,
            SaSi_RSA_DATA_POINTER_INVALID_ERROR,
            SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR,
            SaSi_RSA_INVALID_MESSAGE_DATA_SIZE,
            SaSi_RSA_INVALID_MESSAGE_VAL
 */

CEXPORT_C SaSiError_t SaSi_RSA_PRIM_Decrypt_MTK(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                SaSi_RSAPrimeData_t *PrimeData_ptr, uint8_t *Data_ptr,
                                                uint16_t DataSize, uint8_t *Output_ptr)
{
    /* FUNCTION LOCAL DECLERATIONS */

    /* the counter compare result */
    SaSi_COMMON_CmpCounter_t CounterCmpResult;

    /* the private key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    /* the modulus size in bytes */
    uint32_t nSizeInBytes;

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters pointers validity .......... */
    /* -------------------------------------------------------------------- */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the Prime Data pointer .................... */
    if (PrimeData_ptr == NULL)
        return SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* if the users Data pointer is NULL return an error */
    if (Data_ptr == NULL)
        return SaSi_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the users Output pointer is NULL return an error */
    if (Output_ptr == NULL)
        return SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* setting the modulus size in bytes */
    nSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->nSizeInBits);

    /* if the data size is 0 or great than modulus size - return an error */
    if (DataSize == 0 || DataSize > nSizeInBytes)
        return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;

    /* ................ copying the input data to the buffer .............. */
    /* -------------------------------------------------------------------- */

    /* clear the input data */
    SaSi_PalMemSetZero(PrimeData_ptr->DataIn, sizeof(PrimeData_ptr->DataIn));

    /* copy the input data to the aligned buffer on the data handler in little endian format */
    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrimeData_ptr->DataIn, 4 * ((nSizeInBytes + 3) / 4), Data_ptr,
                                                        DataSize);
    if (Error)
        goto End;

    /* .. checking the message value it must be less then the modulus .. */
    /* ----------------------------------------------------------------- */
    CounterCmpResult = SaSi_COMMON_CmpLsWordsUnsignedCounters(PrimeData_ptr->DataIn, (uint16_t)(nSizeInBytes + 3) / 4,
                                                              PrivKey_ptr->n, (uint16_t)(nSizeInBytes + 3) / 4);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_RSA_INVALID_MESSAGE_VAL;
        goto End;
    }

    /* ..................... executing the encryption ...................... */
    /* --------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_ExecPrivKeyExp(PrivKey_ptr, PrimeData_ptr);

    if (Error != SaSi_OK) {
        goto End;
    }

    /* copy the output data from the aligned words-buffer to the users data in MS-LS bytes order */
    Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(Output_ptr, 4 * ((nSizeInBytes + 3) / 4),
                                                        PrimeData_ptr->DataOut, nSizeInBytes);
    if (Error != SaSi_OK) {
        goto End;
    }

End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Output_ptr, nSizeInBytes);
    }

    /* clear the temp data buffer */
    SaSi_PalMemSetZero(PrimeData_ptr, sizeof(SaSi_RSAPrimeData_t));

    return Error;

} /* END OF SaSi_RSA_PRIM_Decrypt_MTK */
