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
#include "ssi_pal_types.h"
#include "sasi_rsa_error.h"
#include "sasi_hash.h"
#include "sasi_hash_error.h"
#include "sasi_rsa_local.h"
#include "sasi_rsa_prim.h"
#include "sasi_fips_defs.h"

/* *********************** Defines ************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs ************************* */

/* *********************** Global Data *********************** */

#ifdef DEBUG_OAEP_SEED
#include "SaSi_RSA_PSS21_defines.h"
extern uint8_t SaltDB[NUM_OF_SETS_TEST_VECTORS][NUM_OF_TEST_VECTOR_IN_SET][SaSi_RSA_PSS_SALT_LENGTH];
extern uint16_t Global_Set_Index;
extern uint16_t Global_vector_Index;
#endif

/* ************ Private function prototype ************** */

#if !defined(_INTERNAL_SaSi_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_VERIFY_SUPPORT)

/* ******************************************************************************************************* */

/*
   @brief
   RSA_SCHEMES_Encrypt implements the RSAES-OAEP algorithm as defined
   in PKCS#1 v2.1 8.1 and in PKCS#1 v1.5 8.1

        This function combines the RSA encryption primitive and the
        EME-OAEP encoding method, to provide an RSA-based encryption
        method that is semantically secure against adaptive
        chosen-ciphertext attacks. For more details, please refere to
        the PKCS#1 standard.

        The actual macro that will be used by the user is:
        SaSi_RSA_OAEP_Encrypt       - for v2.1
        SaSi_RSA_PKCS1v15_Encrypt - for v1.5

   @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param[in] UserPubKey_ptr - A pointer to the public key data structure of the User.
   @param[in] PrimeData_ptr - A pointer to a SaSi_RSAPrimeData_t
                                that is used for the Encryption operation
   @param[in] hashFunc - The hash function to be used.
                         The hash functions supported: SHA1, SHA-256/284/512,
                         MD5 (MD5 - allowed only for PKCS#1 v1.5).
   @param[in] L - The label input pointer. Relevant for PKCS#1 Ver2.1 only, may be NULL also.
                  For PKCS#1 Ver1.5 it is an empty string (NULL).
   @param[in] Llen - The label length. Relevant for PKCS#1 Ver2.1 only (see notes above).
   @param[in] MGF - the mask generation function. PKCS#1 v2.1
                    defines MGF1, so the currently allowed value is SaSi_PKCS1_MGF1.
   @param[in] Data_ptr - Pointer to the data to encrypt.
   @param[in] DataSize - The size, in bytes, of the data to encrypt.
                         \Note: The data size must be:
                            1. for PKCS #1 v.2.1  DataSize <= PrivKey_ptr->N.len - 2*HashLen - 2.
                            2. for PKCS #1 v.1.5  DataSize <= PrivKey_ptr->N.len - 11.
   @param[out] Output_ptr - Pointer to the encrypted data. The size of the data is always
                            equal to the RSA key (modulus) size, in bytes. Therefore the size
                            of allocated buffer must be at least of this size.

   @return SaSiError_t - SaSi_OK, SaSi_BAD_PARAM, SaSi_OUT_OF_RANGE
*/
CEXPORT_C SaSiError_t SaSi_RsaSchemesEncrypt(SaSi_RND_Context_t *rndContext_ptr, SaSi_RSAUserPubKey_t *UserPubKey_ptr,
                                             SaSi_RSAPrimeData_t *PrimeData_ptr, SaSi_RSA_HASH_OpMode_t hashFunc,
                                             uint8_t *L, uint16_t Llen, SaSi_PKCS1_MGF_t MGF, uint8_t *DataIn_ptr,
                                             uint16_t DataInSize, uint8_t *Output_ptr, SaSi_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* The modulus size in Bytes */
    uint16_t K;
    uint8_t HashOutputSize;

    /* In order to save stack memory place -
     * It is required that the Output_ptr is at least the size of the modulus
     * It is also required that the RSA computation is done in-place */
    uint8_t *EB_buff = Output_ptr;

    SaSiRSAPubKey_t *PubKey_ptr;
    SaSi_HASH_OperationMode_t SasiHashOpMode;
    uint32_t PSSize;

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context pointer is NULL return an error */
    if (UserPubKey_ptr == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == NULL)
        return SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* check if the hash operation mode is legal */
    if (hashFunc >= SaSi_RSA_HASH_NumOfModes)
        return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (SaSi_RSA_NumOfMGFFunctions <= MGF)
        return SaSi_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= SaSi_RSA_NumOf_PKCS1_versions)
        return SaSi_RSA_PKCS1_VER_ARG_ERROR;

    /* if the users Data In pointer is illegal return an error */
    /* note - it is allowed to encrypt a message of size zero ; only on this case a NULL is allowed */
    if (DataIn_ptr == NULL && DataInSize != 0)
        return SaSi_RSA_DATA_POINTER_INVALID_ERROR;

    /* If the output pointer is NULL return Error */
    if (Output_ptr == NULL)
        return SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;

    PubKey_ptr = (SaSiRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

    if (UserPubKey_ptr->valid_tag != SaSi_RSA_PUB_KEY_VALIDATION_TAG)
        return SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

    if (Llen == 0)
        L = NULL;

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initialize K with the modulus size in Bytes */
    K = (uint16_t)CALC_FULL_BYTES(PubKey_ptr->nSizeInBits);

#ifdef DEBUG
    /* Initialize the Output_ptr to Zero */
    SaSi_PalMemSetZero(EB_buff, K);
#endif

    /* -------------------------------------------------------*
     * Perform Encoding and Encryption accordimg to PKCS1      *
     * Versions: VER21 or VER15                              *
     * ------------------------------------------------------- */

    switch (PKCS1_ver) {
#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_15_SUPPORT
    case SaSi_PKCS1_VER15:
        /* -------------------------------------------------------*
         * Step 1 : Check modulus and data sizes              *
         * ------------------------------------------------------- */
        /* Check the modulus size is legal */
        if (K < 3 + PS_MIN_LEN)
            return SaSi_RSA_INVALID_MODULUS_SIZE;

        if (DataInSize + 3 + PS_MIN_LEN > K)
            return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;
        /* size of PS buffer, it is >= PS_MIN_LEN  */
        PSSize = K - 3 - DataInSize;

        /* -------------------------------------------------------*
         * Step 2 :  Encode the message                          *
         * ------------------------------------------------------- */

        EB_buff[0] = 0x00; /* set the 00 */
        EB_buff[1] = 0x02; /* Block type for EME-PKCS1-v1_5 */

        /* Generate random non-zero bytes for PS */
        Error = RsaGenRndNonZeroVect(rndContext_ptr, &EB_buff[2], PSSize);
        if (Error != SaSi_OK) {
            goto End;
        }
        /* 0-byte after PS */
        EB_buff[K - DataInSize - 1] = 0x00;
        /* Copy the message data */
        SaSi_PalMemCopy(&EB_buff[K - DataInSize], DataIn_ptr, DataInSize);

        break;
#endif

#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_21_SUPPORT

    /* get SaSi Hash parameters */
    case SaSi_PKCS1_VER21:

        switch (hashFunc) {
        case SaSi_RSA_HASH_MD5_mode: /* MD5 is not reccomended in PKCS1 ver 2.1 standard,
                                       hence it is not supported */
            return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        case SaSi_RSA_HASH_SHA1_mode:
            HashOutputSize = SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE;
            SasiHashOpMode = SaSi_HASH_SHA1_mode; /* changing the hash mode to SaSi definition */
            break;
        case SaSi_RSA_HASH_SHA224_mode:
            HashOutputSize = SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE;
            SasiHashOpMode = SaSi_HASH_SHA224_mode; /* changing the hash mode to SaSi definition */
            break;
        case SaSi_RSA_HASH_SHA256_mode:
            HashOutputSize = SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE;
            SasiHashOpMode = SaSi_HASH_SHA256_mode; /* changing the hash mode to SaSi definition */
            break;
        case SaSi_RSA_HASH_SHA384_mode:
            HashOutputSize = SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE;
            SasiHashOpMode = SaSi_HASH_SHA384_mode; /* changing the hash mode to SaSi definition */
            break;
        case SaSi_RSA_HASH_SHA512_mode:
            HashOutputSize = SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE;
            SasiHashOpMode = SaSi_HASH_SHA512_mode; /* changing the hash mode to SaSi definition */
            break;
        default:
            return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        }

        /* if mLen>k-2*hLen-2 output message too long */
        if ((uint32_t)DataInSize + 2 * HashOutputSize + 2 > K)
            return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;

        /* -------------------------------------------------------*
         * Step 2 : Apply the EME-OAEP encoding operation to     *
         *   the message M and the label L to produce a          *
         *   ciphertext of length k octets.                      *
         * ------------------------------------------------------- */

        Error = SaSi_RSA_PSS_OAEPEncode(rndContext_ptr, /* ! random functions comtext */
                                        SasiHashOpMode, /* ! hash operation mode enum */
                                        MGF,            /* ! MGF function mode enum */
                                        DataIn_ptr,     /* ! input data to be encrypted */
                                        DataInSize,     /* ! input data size bytes */
                                        L,              /* ! label */
                                        Llen,           /* ! label length bytes */
                                        K,              /* ! modulus size in bytes */
                                        PrimeData_ptr,  /* ! temp buffer 1 structure for imternal use */
                                        EB_buff,        /* ! temp buffer 2 for imternal use */
                                        PKCS1_ver /* ! PKCS1 version enum */);
        if (Error != SaSi_OK) {
            goto End;
        }
        break;
#endif
    default:
        return SaSi_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* ------------------------------------------- */
    /* Step 3 : RSA computation                  */
    /* ------------------------------------------- */

    Error = SaSi_RSA_PRIM_Encrypt_MTK(UserPubKey_ptr, PrimeData_ptr, EB_buff, K, Output_ptr);
End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Output_ptr, K);
    }
    /* clear the temp data buffer */
    SaSi_PalMemSetZero(PrimeData_ptr, sizeof(SaSi_RSAPrimeData_t));

    return Error;

} /* END OF SaSi_RsaSchemesEncrypt */
#endif /* !defined(_INTERNAL_SaSi_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_VERIFY_SUPPORT) */

#if !defined(_INTERNAL_SaSi_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_SIGN_SUPPORT)
/* ******************************************************************************************************* */
/*
   @brief
   RSA_SCHEMES_Decrypt implements the RSAES-OAEP algorithm as defined
   in PKCS#1 v2.1 8.1 and in PKCS#1 v1.5

           This function combines the RSA decryption primitive and the
           EME-OAEP decoding method, to provide an RSA-based decryption
           method that is semantically secure against adaptive
           chosen-ciphertext attacks. For more details, please refer to
           the PKCS#1 standard.

   @param[in] UserPrivKey_ptr - Pointer to the private key data structure.
                   \Note: The representation (pair or quintuple)
                    and hence the algorithm (CRT or not) is determined
                    by the Private Key data structure. Using SaSi_Build_PrivKey
                    or SaSi_Build_PrivKeyCRT determines which algorithm will be used.

   @param[in] PrimeData_ptr - Pointer to a SaSi_RSAPrimeData_t which is used for the
                                                          Encryption operation

   @param[in] hashFunc - The hash function to be used.
                         The hash functions supported: SHA1, SHA-256/284/512,
                         MD5 (MD5 - allowed only for PKCS#1 v1.5).

   @param[in] L - The label input pointer. Relevant for PKCS#1 Ver2.1 only, may be NULL also.
                  For PKCS#1 Ver1.5 it is an empty string (NULL).
   @param[in] Llen - The label length. Relevant for PKCS#1 Ver2.1 only (see notes above).
   @param[in] MGF - The mask generation function. PKCS#1 v2.1 defines MGF1,
                    so the only value allowed here is SaSi_PKCS1_MGF1.
   @param[in] Data_ptr - Pointer to the data to decrypt.
   @param[in] DataSize - The size, in bytes, of the data to decrypt.
                        \Note: The size must be = the size of the modulus.

   @param[out] Output_ptr - Pointer to the decrypted data, the size of the buffer in bytes
                must be not less than the actual size of Encrypted message, if it is known,
                else the output buffer size must be :
                1. for PKCS #1 v.2.1  *OutputSize_ptr >= PrivKey_ptr->N.len - 2*HashLen - 2.
                2. for PKCS #1 v.1.5  *OutputSize_ptr >= PrivKey_ptr->N.len - 11.
   @param[in/out] OutputSize_ptr - The size of the user passed Output_ptr buffer in bytes [in] and
                actual size of decrypted message [out].
                The minimal input size value of *OutputSize_ptr is described above.
                This value is updated with the actual number of bytes that
                are loaded to Output_ptr buffer byDecrypt function.

   @return SaSiError_t - SaSi_OK or appropriate Error message defined in the RSA module.
*/
CEXPORT_C SaSiError_t SaSi_RsaSchemesDecrypt(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, SaSi_RSAPrimeData_t *PrimeData_ptr,
                                             SaSi_RSA_HASH_OpMode_t hashFunc, uint8_t *L, uint16_t Llen,
                                             SaSi_PKCS1_MGF_t MGF, uint8_t *DataIn_ptr, uint16_t DataInSize,
                                             uint8_t *Output_ptr, uint16_t *OutputSize_ptr,
                                             SaSi_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;
    uint16_t K; /* The modulus size in Bytes */
    uint8_t EB_buff[SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * SASI_32BIT_WORD_SIZE];
    uint16_t HashOutputSizeBytes;
    SaSiRSAPrivKey_t *PrivKey_ptr;
    /* The Hash enum sent to the lower level functions */
    /* The initialization is to eliminate a warning of uninitialized variable */
    SaSi_HASH_OperationMode_t SasiHashOpMode = SaSi_HASH_NumOfModes;

    int32_t PSSize, i;

    /* FUNCTION LOGIC */

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();
    /* initialize the HASH mode as SHA1 - default */
    SasiHashOpMode = SaSi_HASH_SHA1_mode;

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    if (PrimeData_ptr == NULL)
        return SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* check if the hash operation mode is legal */
    if (hashFunc >= SaSi_RSA_HASH_NumOfModes)
        return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (SaSi_RSA_NumOfMGFFunctions <= MGF)
        return SaSi_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= SaSi_RSA_NumOf_PKCS1_versions)
        return SaSi_RSA_PKCS1_VER_ARG_ERROR;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL)
        return SaSi_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the data size is zero or larger then 2^29 (to prevent an overflow on the transition to bits )
       return error */
    if (DataInSize == 0)
        return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;

    /* If the output pointer is NULL return Error */
    if (Output_ptr == NULL)
        return SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;

    /* If the output size pointer is NULL return error */
    if (OutputSize_ptr == NULL)
        return SaSi_RSA_DECRYPT_OUTPUT_SIZE_POINTER_ERROR;

    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;
    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    if (Llen == 0)
        L = NULL;

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initialize K with the modulus size in Bytes */
    K = (uint16_t)(CALC_FULL_BYTES(PrivKey_ptr->nSizeInBits));

    /* Length Checking - both for Ver 1.5 and 2.1 */
    if (DataInSize != K)
        return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;

    /* ------------------------------------------------- */
    switch (PKCS1_ver) {
#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_15_SUPPORT
    case SaSi_PKCS1_VER15:
        /* Check the modulus size is legal */
        if (K < 11)
            return SaSi_RSA_INVALID_MODULUS_SIZE;
        break;
#endif

#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_21_SUPPORT
    case SaSi_PKCS1_VER21:

        switch (hashFunc) {
        case SaSi_RSA_HASH_MD5_mode:
            /* MD5 is not recommended in PKCS1 ver 2.1 standard, hence it is not supported */
            return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        case SaSi_RSA_HASH_SHA1_mode:
            SasiHashOpMode      = SaSi_HASH_SHA1_mode; /* changing the hash mode to SaSi definition */
            HashOutputSizeBytes = SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_RSA_HASH_SHA224_mode:
            SasiHashOpMode      = SaSi_HASH_SHA224_mode;
            HashOutputSizeBytes = SaSi_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_RSA_HASH_SHA256_mode:
            SasiHashOpMode      = SaSi_HASH_SHA256_mode;
            HashOutputSizeBytes = SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_RSA_HASH_SHA384_mode:
            SasiHashOpMode      = SaSi_HASH_SHA384_mode;
            HashOutputSizeBytes = SaSi_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_RSA_HASH_SHA512_mode:
            SasiHashOpMode      = SaSi_HASH_SHA512_mode;
            HashOutputSizeBytes = SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
            break;
        default:
            return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        }

        /* Checking that the modulus have enough large */
        if (2 * HashOutputSizeBytes + 2 > K)
            return SaSi_RSA_INVALID_MODULUS_SIZE;
        break;
#endif
    default:
        return SaSi_RSA_PKCS1_VER_ARG_ERROR;

    } /* end of switch(PKCS1_ver) */

    /* ------------------------------------------- */
    /* Step 2 <b> : RSA computation              */
    /* ------------------------------------------- */
    Error = SaSi_RSA_PRIM_Decrypt_MTK(UserPrivKey_ptr, PrimeData_ptr, DataIn_ptr, DataInSize, EB_buff);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ----------------------------------------------*
     * Step 3 :  EME-OAEP Decoding            *
     * ---------------------------------------------- */

    /* for all modes */
    if (EB_buff[0] != 0x00) {
        Error = SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
        goto End;
    }

    /* ------------------------------------------------*
     * Perform decoding operation according to the    *
     * encoded message EM choosen PKCS1 version       *
     * ------------------------------------------------ */

    switch (PKCS1_ver) {
#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_15_SUPPORT
    case SaSi_PKCS1_VER15:

        /* ------------------------------------------------*
         * Check parameters of decrypted buffer,          *
         *    EM= 0x00||0x02||PS||0x00||M                 *
         * If EM[0] != 0 or EM[1] != 2 or no 0-byte       *
         * after PS or PS length < 8, then output "error" *
         * and stop. Output the message M.              *
         * ------------------------------------------------ */

        if (EB_buff[1] != 0x02 /* Block type for EME-PKCS1-v1_5 */) {
            Error = SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
            goto End;
        }

        /* find next 0-byte after PS */
        for (i = 2; i < K; i++) {
            if (EB_buff[i] == 0x00)
                break;
        }
        /* if byte 0 not present */
        if (i == K) {
            Error = SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
            goto End;
        }

        /* check PS size >= 8 */
        PSSize = i - 2;
        if (PSSize < PS_MIN_LEN) {
            Error = SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
            goto End;
        }

        if (PSSize + 3 > K) {
            Error = SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
            goto End;
        }

        /* check size of output buffer  */
        if (*OutputSize_ptr < K - 3 - PSSize) {
            Error = SaSi_RSA_15_ERROR_IN_DECRYPTED_DATA_SIZE;
            goto End;
        } else {
            *OutputSize_ptr = K - 3 - PSSize; /* output actual size of decrypted message */
        }

        /* copy the message into output buffer */
        SaSi_PalMemCopy(Output_ptr, &EB_buff[3 + PSSize], *OutputSize_ptr);

        break;
#endif

#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_21_SUPPORT
    case SaSi_PKCS1_VER21:

        /* ------------------------------------------------*
         * Apply the EME-OAEP decoding operation to the   *
         * encoded message EM and the parameter          *
         * L to recover a message M:                      *
         * M = EME-OAEP-DECODE (EM, L)                    *
         * If the decoding operation outputs              *
         * "decoding error," then output                  *
         * "decryption error" and stop.                   *
         * ------------------------------------------------ */
        Error = SaSi_RSA_PSS_OAEPDecode(SasiHashOpMode, MGF, &EB_buff[1], (uint16_t)(K - 1), L, Llen, PrimeData_ptr,
                                        Output_ptr, OutputSize_ptr);
        break;
#endif
    default:
        Error = SaSi_RSA_PKCS1_VER_ARG_ERROR;
    }
End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Output_ptr, *OutputSize_ptr);
        *OutputSize_ptr = 0;
    }
    /* clear the temp data buffer */
    SaSi_PalMemSetZero(PrimeData_ptr, sizeof(SaSi_RSAPrimeData_t));

    return Error;

} /* END OF SaSi_RsaSchemesDecrypt */

/* ******************************************************************************************************* */
/* !
@brief This function implements the a private encrypt operation.
       This function combines the RSA decryption primitive and the
       EMSA-PKCS1-v1_5 encoding method, to provide an RSA-based encryption
       method.

@return SaSi_OK on success.
@return A non-zero value from sasi_rsa_error.h on failure.
*/
CEXPORT_C SaSiError_t SaSi_RSA_PKCS1v15_PrivateEncrypt(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                       SaSi_RSAPrimeData_t *PrimeData_ptr, uint8_t *DataIn_ptr,
                                                       uint16_t DataInSize, uint8_t *Output_ptr)
{
    /* FUNCTION DECLARATIONS */

    SaSiError_t Error = SaSi_OK;

    /* The modulus size in Bytes */
    uint16_t K;

    /* In order to save stack memory place -
     * It is required that the Output_ptr is at least the size of the modulus
     * It is also required that the RSA computation is done in-place */
    uint8_t *EB_buff = Output_ptr;
    SaSiRSAPrivKey_t *PrivKey_ptr;
    uint32_t PSSize;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context pointer is DX_NULL return an error */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == NULL)
        return SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* if the users Data In pointer is illegal return an error */
    /* note - it is allowed to encrypt a message of size zero ; only on this case a NULL is allowed */
    if (DataIn_ptr == NULL && DataInSize != 0)
        return SaSi_RSA_DATA_POINTER_INVALID_ERROR;

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == NULL)
        return SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;

    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initialize K with the modulus size in Bytes */
    K = ((uint16_t)PrivKey_ptr->nSizeInBits + 7) / 8;

#ifdef DEBUG
    /* Initialize the Output_ptr to Zero */
    SaSi_PalMemSet(EB_buff, 0, K);
#endif

    /* -------------------------------------------------------*
     * Perform Encoding and Encryption accordimg to PKCS1      *
     * Versions:  VER15                                      *
     * ------------------------------------------------------- */

    /* -------------------------------------------------------*
     * Step 1 : Check modulus and data sizes              *
     * ------------------------------------------------------- */
    /* Check the modulus size is legal */
    if (K < 3 + PS_MIN_LEN)
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    if (DataInSize + 3 + PS_MIN_LEN > K)
        return SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;
    /* size of PS buffer, it is >= PS_MIN_LEN  */
    PSSize = K - 3 - DataInSize;

    /* -------------------------------------------------------*
     * Step 2 :  Encode the message                          *
     *                                                       *
     *   formating for EMSA-PKCS1-v1_5:                      *
     *          00 || 01 || PS || 00 || T                *
     * ------------------------------------------------------- */
    EB_buff[0] = 0x00; /* set the 00 */
    EB_buff[1] = 0x01; /* Block type for EME-PKCS1-v1_5 */

    SaSi_PalMemSet(&EB_buff[2], 0xFF, PSSize);

    /* 0-byte after PS */
    EB_buff[K - DataInSize - 1] = 0x00;
    /* Copy the message data */
    SaSi_PalMemCopy(&EB_buff[K - DataInSize], DataIn_ptr, DataInSize);

    /* ------------------------------------------- */
    /* Step 3 : RSA computation                  */
    /* ------------------------------------------- */

    Error = SaSi_RSA_PRIM_Decrypt_MTK(UserPrivKey_ptr, PrimeData_ptr, EB_buff, K, Output_ptr);

    return Error;
}
#endif /* !defined(_INTERNAL_SaSi_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_VERIFY_SUPPORT) */
