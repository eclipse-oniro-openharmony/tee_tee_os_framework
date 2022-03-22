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
#include "sasi_rsa_error.h"
#include "sasi_rsa_local.h"
#include "pka.h"
#include "llf_rsa.h"
#include "llf_rsa_public.h"
#include "llf_rsa_private.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs ************************* */

/* *********************** Global Data ********************** */

/* *********************** Public Functions **************************** */

/* *************************************************************************************** */
/*
 * @brief SaSi_RSA_Build_PubKey_MTK populates a SaSiRSAPubKey_t structure with
 *       the provided modulus and exponent.
 *
 *    Assumption : the modulus and the exponent are presented in big endian.
 *
 * @param[out] PubKey_ptr - a pointer to the public key structure. This structure will be
 *            used as an input to the SaSi_RSA_PRIM_Encrypt_MTK API.
 *
 * @param[in] Exponent_ptr - a pointer to the exponent stream of bytes ( Big endian ).
 * @param[in] ExponentSize - The size of the exponent in bytes.
 * @param[in] Modulus_ptr  - a pointer to the modulus stream of bytes ( Big endian ) the MS
 *           bit must be set to '1'.
 * @param[in] ModulusSize  - The size of the modulus in bytes. Sizes supported according to
 *           used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CEXPORT_C SaSiError_t SaSi_RSA_Build_PubKey_MTK(SaSi_RSAUserPubKey_t *UserPubKey_ptr, uint8_t *Exponent_ptr,
                                                uint16_t ExponentSize, uint8_t *Modulus_ptr, uint16_t ModulusSize)
{
    /* FUNCTION DECLARATIONS */

    /* the counter compare result */
    SaSi_COMMON_CmpCounter_t CounterCmpResult;

    /* the effective size in bits of the modulus buffer */
    uint32_t ModulusEffectiveSizeInBits;

    /* the effective size in bits of the exponent buffer */
    uint32_t ExponentEffectiveSizeInBits;

    /* the public key database pointer */
    SaSiRSAPubKey_t *PubKey_ptr;

    /* the Error return code identifier */
    SaSiError_t Error = SaSi_OK;

    /* Max Size of buffers in Key structure */
    uint32_t buffSizeBytes = SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES;

    /* FUNCTION LOGIC */
    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (UserPubKey_ptr == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (Exponent_ptr == NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == NULL)
        return SaSi_RSA_INVALID_MODULUS_POINTER_ERROR;

    if (ModulusSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    if (ExponentSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    /* .................. copy the buffers to the key handle structure .... */
    /* -------------------------------------------------------------------- */
    /* setting the pointer to the key database */
    PubKey_ptr = (SaSiRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

    /* clear the public key db */
    SaSi_PalMemSetZero(PubKey_ptr, sizeof(SaSiRSAPubKey_t));

    /* loading the buffers to little endian order of words in array; each word is loaded according to CPU endianness */
    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PubKey_ptr->n, buffSizeBytes, Modulus_ptr, ModulusSize);
    if (Error)
        return Error;

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PubKey_ptr->e, buffSizeBytes, Exponent_ptr, ExponentSize);
    if (Error) {
        goto End;
    }

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* .......... initializing the effective counters size in bits .......... */
    ModulusEffectiveSizeInBits  = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PubKey_ptr->n, (ModulusSize + 3) / 4);
    ExponentEffectiveSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PubKey_ptr->e, (ExponentSize + 3) / 4);

    /* .................. checking the validity of the counters ............... */
    /* ------------------------------------------------------------------------ */
    if ((ModulusEffectiveSizeInBits < SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (ModulusEffectiveSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        Error = SaSi_RSA_INVALID_MODULUS_SIZE;
        goto End;
    }
    /*  verifying the modulus is odd  */
    if ((PubKey_ptr->n[0] & 1UL) == 0) {
        Error = SaSi_RSA_MODULUS_EVEN_ERROR;
        goto End;
    }

    /*  checking the exponent size is not 0 in bytes */
    if (ExponentEffectiveSizeInBits == 0) {
        Error = SaSi_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /*  verifying the exponent is less then the modulus */
    CounterCmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(Exponent_ptr, ExponentSize, Modulus_ptr, ModulusSize);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /*  verifying the exponent is not less then 3 */
    if (ExponentEffectiveSizeInBits < 32 && PubKey_ptr->e[0] < SaSi_RSA_MIN_PUB_EXP_VALUE) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* ................. building the structure ............................. */
    /* ---------------------------------------------------------------------- */

    /* setting the modulus and exponent size in bits */
    PubKey_ptr->nSizeInBits = ModulusEffectiveSizeInBits;
    PubKey_ptr->eSizeInBits = ExponentEffectiveSizeInBits;

    /* ................ initialize the low level data .............. */
    Error = LLF_PKI_RSA_InitPubKeyDb(PubKey_ptr);

    if (Error)
        goto End;

    /* ................ set the tag ................ */
    UserPubKey_ptr->valid_tag = SaSi_RSA_PUB_KEY_VALIDATION_TAG;

    /* ................. end of the function .................................. */
    /* ------------------------------------------------------------------------ */

End:

    /* if the structure created is not valid - clear it */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(UserPubKey_ptr, sizeof(SaSi_RSAUserPubKey_t));
        return Error;
    }

    return SaSi_OK;

} /* END OF SaSi_RSA_Build_PubKey_MTK */

/* *************************************************************************************** */
/*
 * @brief SaSi_RSA_Build_PrivKey_MTK populates a SaSiRSAPrivKey_t structure with
 *        the provided modulus and exponent, marking the key as a "non-CRT" key.
 *
 *        Assumption : the modulus and the exponent are presented in big endian.
 *
 * @param[out] UserPrivKey_ptr - a pointer to the public key structure. this structure will be used as
 *                          an input to the SaSi_RSA_PRIM_Decrypt_MTK API.
 * @param[in] PrivExponent_ptr - a pointer to the private exponent stream of bytes ( Big endian ).
 * @param[in] PrivExponentSize - the size of the private exponent in bytes.
 * @param[in] Exponent_ptr - a pointer to the exponent stream of bytes ( Big endian ).
 * @param[in] ExponentSize - the size of the exponent in bytes.
 * @param[in] Modulus_ptr  - a pointer to the modulus stream of bytes ( Big endian ) the MS
 *            bit must be set to '1'.
 * @param[in] ModulusSize  - the size of the modulus in bytes. Sizes supported according to
 *            used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                       value MODULE_* as defined in ...
 *
 */
CEXPORT_C SaSiError_t SaSi_RSA_Build_PrivKey_MTK(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *PrivExponent_ptr,
                                                 uint16_t PrivExponentSize, uint8_t *PubExponent_ptr,
                                                 uint16_t PubExponentSize, uint8_t *Modulus_ptr, uint16_t ModulusSize)
{
    /* FUNCTION DECLARATIONS */

    /* the counter compare result */
    SaSi_COMMON_CmpCounter_t CounterCmpResult;

    /* the effective size in bits of the modulus buffer */
    uint32_t ModulusEffectiveSizeInBits;

    /* the effective sizes in bits of the private and public exponents */
    uint32_t PrivExponentEffectiveSizeInBits, PubExponentEffectiveSizeInBits;

    /* the private key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    /* Max Size of buffers in Key structure */
    uint32_t buffSizeBytes = SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES;

    /* the Error return code identifier */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the exponents pointers ........... */
    if (PrivExponent_ptr == NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == NULL)
        return SaSi_RSA_INVALID_MODULUS_POINTER_ERROR;

    /* ...... checking the validity of the modulus size, private exponent can not be more than 256 bytes ..............
     */
    if (ModulusSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    if (PrivExponentSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    if (PubExponent_ptr != NULL && PubExponentSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    /* .................. copy the buffers to the key handle structure .... */
    /* -------------------------------------------------------------------- */

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* clear the private key db */
    SaSi_PalMemSetZero(PrivKey_ptr, sizeof(SaSiRSAPrivKey_t));

    /* loading the buffers to little endian order of words in array; each word is loaded according to CPU endianness */
    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->n, buffSizeBytes, Modulus_ptr, ModulusSize);
    if (Error != SaSi_OK)
        return Error;

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.NonCrt.d, buffSizeBytes,
                                                        PrivExponent_ptr, PrivExponentSize);
    if (Error != SaSi_OK)
        goto End;

    /* get actual sizes of modulus and private exponent */
    ModulusEffectiveSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->n, (ModulusSize + 3) / 4);

    PrivExponentEffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.NonCrt.d, (PrivExponentSize + 3) / 4);

    /* .................. checking the validity of the counters ............... */
    /* ------------------------------------------------------------------------ */

    /*  checking the size of the modulus  */
    if ((ModulusEffectiveSizeInBits < SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (ModulusEffectiveSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        Error = SaSi_RSA_INVALID_MODULUS_SIZE;
        goto End;
    }

    /*  verifying the modulus is odd  */
    if ((PrivKey_ptr->n[0] & 1UL) == 0) {
        Error = SaSi_RSA_MODULUS_EVEN_ERROR;
        goto End;
    }

    /*  checking the priv. exponent size is not 0 in bytes */
    if (PrivExponentEffectiveSizeInBits == 0) {
        Error = SaSi_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifying the priv. exponent is less then the modulus */
    CounterCmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(PrivExponent_ptr, PrivExponentSize, Modulus_ptr, ModulusSize);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* verifying the priv. exponent is not less then 1 */
    if (PrivExponentEffectiveSizeInBits < 32 && PrivKey_ptr->PriveKeyDb.NonCrt.d[0] < SaSi_RSA_MIN_PRIV_EXP_VALUE) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /*  checking that the public exponent is an integer between 3 and modulus - 1 */
    if (PubExponent_ptr != NULL) {
        /* loading the buffer to little endian order of words in array; each word is loaded according to CPU endianness
         */
        Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.NonCrt.e, buffSizeBytes,
                                                            PubExponent_ptr, PubExponentSize);
        if (Error) {
            goto End;
        }

        PubExponentEffectiveSizeInBits =
            SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.NonCrt.e, (PubExponentSize + 3) / 4);

        /* verifying that the exponent is not less than 3 */
        if (PubExponentEffectiveSizeInBits < 32 && PrivKey_ptr->PriveKeyDb.NonCrt.e[0] < SaSi_RSA_MIN_PUB_EXP_VALUE) {
            Error = SaSi_RSA_INVALID_EXPONENT_VAL;
            goto End;
        }

        /* verifying that the public exponent is less than the modulus */
        CounterCmpResult =
            SaSi_COMMON_CmpMsbUnsignedCounters(PubExponent_ptr, PubExponentSize, Modulus_ptr, ModulusSize);

        if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
            Error = SaSi_RSA_INVALID_EXPONENT_VAL;
            goto End;
        }
    } else {
        PubExponentEffectiveSizeInBits = 0;
    }

    /* ................. building the structure ............................. */
    /* ---------------------------------------------------------------------- */

    /* set the mode to non CRT mode */
    PrivKey_ptr->OperationMode = SaSi_RSA_NoCrt;

    /* set the key source as external */
    PrivKey_ptr->KeySource = SaSi_RSA_ExternalKey;

    /* setting the modulus and exponent size in bits */
    PrivKey_ptr->nSizeInBits                   = ModulusEffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits = PrivExponentEffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits = PubExponentEffectiveSizeInBits;

    /* ................ initialize the low level data .............. */
    Error = LLF_PKI_RSA_InitPrivKeyDb(PrivKey_ptr);

    if (Error) {
        goto End;
    }

    /* ................ set the tag ................ */
    UserPrivKey_ptr->valid_tag = SaSi_RSA_PRIV_KEY_VALIDATION_TAG;

    /* ................. end of the function .................................. */
    /* ------------------------------------------------------------------------ */

End:

    /* if the structure created is not valid - clear it */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(UserPrivKey_ptr, sizeof(SaSi_RSAUserPrivKey_t));
    }

    return Error;

} /* END OF SaSi_RSA_Build_PrivKey_MTK */

/* *****************************************************************************************

   @brief SaSi_RSA_Build_PrivKeyCRT_MTK populates a SaSiRSAPrivKey_t structure with
      the provided parameters, marking the key as a "CRT" key.

    Note: The "First" factor P must be great, than the "Second" factor Q.


   @param[out] UserPrivKey_ptr - A pointer to the public key structure.
                This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.
   @param[in] P_ptr - A pointer to the first factor stream of bytes (Big-Endian format)
   @param[in] PSize - The size of the first factor, in bytes.
   @param[in] Q_ptr - A pointer to the second factor stream of bytes (Big-Endian format)
   @param[in] QSize - The size of the second factor, in bytes.
   @param[in] dP_ptr - A pointer to the first factor's CRT exponent stream of bytes (Big-Endian format)
   @param[in] dPSize - The size of the first factor's CRT exponent, in bytes.
   @param[in] dQ_ptr - A pointer to the second factor's CRT exponent stream of bytes (Big-Endian format)
   @param[in] dQSize - The size of the second factor's CRT exponent, in bytes.
   @param[in] qInv_ptr - A pointer to the first CRT coefficient stream of bytes (Big-Endian format)
   @param[in] qInvSize - The size of the first CRT coefficient, in bytes.

*/
CEXPORT_C SaSiError_t SaSi_RSA_Build_PrivKeyCRT_MTK(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *P_ptr,
                                                    uint16_t PSize, uint8_t *Q_ptr, uint16_t QSize, uint8_t *dP_ptr,
                                                    uint16_t dPSize, uint8_t *dQ_ptr, uint16_t dQSize,
                                                    uint8_t *qInv_ptr, uint16_t qInvSize)
{
    /* FUNCTION DECLARATIONS */

    /* the counter compare result */
    SaSi_COMMON_CmpCounter_t CounterCmpResult;

    /* the effective size in bits of the modulus factors buffer */
    uint32_t P_EffectiveSizeInBits;
    uint32_t Q_EffectiveSizeInBits;
    uint32_t dP_EffectiveSizeInBits;
    uint32_t dQ_EffectiveSizeInBits;
    uint32_t qInv_EffectiveSizeInBits;
    uint32_t ModulusEffectiveSizeInBits;

    /* the private key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    /* Max Size of buffers in CRT Key structure */
    uint32_t buffSizeBytes = 4 * ((PSize + 3) / 4) + 4;

    /* the Error return code identifier */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* checking the first factor pointer validity */
    if (P_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR;

    /* checking the second factor pointer validity */
    if (Q_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR;

    /* checking the first factor exponent pointer validity */
    if (dP_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR;

    /* checking the second factor exponent pointer validity */
    if (dQ_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR;

    /* checking the CRT coefficient */
    if (qInv_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR;

    /* checking the input sizes */
    if (PSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES / 2 ||
        QSize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES / 2) {
        return SaSi_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
    }

    if (dPSize > PSize || dQSize > QSize || qInvSize > PSize) {
        return SaSi_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
    }

    /* verifying the first factor exponent is less then the first factor */
    CounterCmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(dP_ptr, dPSize, P_ptr, PSize);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXPONENT_VAL;
    }

    /* verifying the second factor exponent is less then the second factor */
    CounterCmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(dQ_ptr, dQSize, Q_ptr, QSize);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXPONENT_VAL;
    }

    /* verifying the CRT coefficient is less then the first factor */
    CounterCmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(qInv_ptr, qInvSize, P_ptr, PSize);

    if (CounterCmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        return SaSi_RSA_INVALID_CRT_COEFF_VAL;
    }

    /* .................. copy the buffers to the key handle structure .... */
    /* -------------------------------------------------------------------- */

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* clear the private key db */
    SaSi_PalMemSetZero(PrivKey_ptr, sizeof(SaSiRSAPrivKey_t));

    /* load the buffers to the data base */
    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.Crt.P, buffSizeBytes, P_ptr, PSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.Crt.Q, buffSizeBytes, Q_ptr, QSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.Crt.dP, buffSizeBytes, dP_ptr, dPSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.Crt.dQ, buffSizeBytes, dQ_ptr, dQSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(PrivKey_ptr->PriveKeyDb.Crt.qInv, buffSizeBytes, qInv_ptr,
                                                        qInvSize);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* initializing the effective counters size in bits */
    P_EffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.Crt.P, (PSize + 3) / 4);

    Q_EffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.Crt.Q, (QSize + 3) / 4);

    dP_EffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.Crt.dP, (dPSize + 3) / 4);

    dQ_EffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.Crt.dQ, (dQSize + 3) / 4);

    qInv_EffectiveSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(PrivKey_ptr->PriveKeyDb.Crt.qInv, (qInvSize + 3) / 4);

    /*  the first factor size is not 0 in bits */
    if (P_EffectiveSizeInBits == 0 || P_EffectiveSizeInBits > 8 * PSize) {
        Error = SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE;
        goto End;
    }

    /* the second factor size is not 0 in bits */
    if (Q_EffectiveSizeInBits == 0 || Q_EffectiveSizeInBits > 8 * QSize) {
        Error = SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE;
        goto End;
    }

    /* checking that sizes of dP, dQ, qInv > 0 */
    if (dP_EffectiveSizeInBits == 0 || dQ_EffectiveSizeInBits == 0 || qInv_EffectiveSizeInBits == 0) {
        Error = SaSi_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
        goto End;
    }

    /* ............... calculate the modulus N ........................... */
    /* -------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_CallRMul(PrivKey_ptr->PriveKeyDb.Crt.P, P_EffectiveSizeInBits, PrivKey_ptr->PriveKeyDb.Crt.Q,
                                 PrivKey_ptr->n);
    if (Error != SaSi_OK) {
        goto End;
    }

    ModulusEffectiveSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(
        PrivKey_ptr->n, (2 * CALC_FULL_32BIT_WORDS(P_EffectiveSizeInBits)));

    /* .................. checking the validity of the counters ............... */
    /* ------------------------------------------------------------------------ */

    /* the size of the modulus  */
    if ((ModulusEffectiveSizeInBits < SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (ModulusEffectiveSizeInBits > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        Error = SaSi_RSA_INVALID_MODULUS_SIZE;
        goto End;
    }

    if ((P_EffectiveSizeInBits + Q_EffectiveSizeInBits != ModulusEffectiveSizeInBits) &&
        (P_EffectiveSizeInBits + Q_EffectiveSizeInBits != ModulusEffectiveSizeInBits - 1)) {
        Error = SaSi_RSA_INVALID_CRT_FIRST_AND_SECOND_FACTOR_SIZE;
        goto End;
    }

    /* ................. building the structure ............................. */
    /* ---------------------------------------------------------------------- */

    /* set the mode to CRT mode */
    PrivKey_ptr->OperationMode = SaSi_RSA_Crt;

    /* set the key source as external */
    PrivKey_ptr->KeySource = SaSi_RSA_ExternalKey;

    /* loading to structure the buffer sizes... */

    PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits    = P_EffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits    = Q_EffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits   = dP_EffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits   = dQ_EffectiveSizeInBits;
    PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits = qInv_EffectiveSizeInBits;
    PrivKey_ptr->nSizeInBits                   = ModulusEffectiveSizeInBits;

    /* ................ initialize the low level data .............. */
    Error = LLF_PKI_RSA_InitPrivKeyDb(PrivKey_ptr);

    if (Error != SaSi_OK) {
        goto End;
    }

    /* ................ set the tag ................ */
    UserPrivKey_ptr->valid_tag = SaSi_RSA_PRIV_KEY_VALIDATION_TAG;

    /* ................. end of the function .................................. */
    /* ------------------------------------------------------------------------ */

End:

    /* if the structure created is not valid - clear it */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(UserPrivKey_ptr, sizeof(SaSi_RSAUserPrivKey_t));
        return Error;
    }

    return Error;

} /* END OF SaSi_RSA_Build_PrivKeyCRT_MTK */

/* *****************************************************************************************
   @brief SaSi_RSA_Get_PubKey_MTK gets the e,n public key from the database.

   @param[in] UserPubKey_ptr - A pointer to the public key structure.
                   This structure is used as input to the SaSi_RSA_PRIM_Encrypt_MTK API.

   @param[out] Exponent_ptr - A pointer to the exponent stream of bytes (Big-Endian format)
   @param[in,out] ExponentSize_ptr - the size of the exponent buffer in bytes, it is updated to the
          actual size of the exponent, in bytes.
   @param[out] Modulus_ptr  - A pointer to the modulus stream of bytes (Big-Endian format).
               The MS (most significant) bit must be set to '1'.
   @param[in,out] ModulusSize_ptr  - the size of the modulus buffer in bytes, it is updated to the
          actual size of the modulus, in bytes.

   NOTE: All members of input UserPrivKey structure must be initialized, including public key
     e pointer and it size.

*/
CEXPORT_C SaSiError_t SaSi_RSA_Get_PubKey_MTK(SaSi_RSAUserPubKey_t *UserPubKey_ptr, uint8_t *Exponent_ptr,
                                              uint16_t *ExponentSize_ptr, uint8_t *Modulus_ptr,
                                              uint16_t *ModulusSize_ptr)
{
    /* LOCAL DECLERATIONS */

    /* the size in bytes of the modulus and the exponent */
    uint32_t nSizeInBytes;
    uint32_t eSizeInBytes;
    /* the public key database pointer */
    SaSiRSAPubKey_t *PubKey_ptr;

    SaSiError_t Error;

    /* FUNCTION DECLERATIONS */

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (UserPubKey_ptr == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (Exponent_ptr == NULL && Modulus_ptr != NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == NULL && Exponent_ptr != NULL)
        return SaSi_RSA_INVALID_MODULUS_POINTER_ERROR;

    if (ExponentSize_ptr == NULL)
        return SaSi_RSA_INVALID_EXP_BUFFER_SIZE_POINTER;

    if (ModulusSize_ptr == NULL)
        return SaSi_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPubKey_ptr->valid_tag != SaSi_RSA_PUB_KEY_VALIDATION_TAG)
        return SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

    /* ...... checking the exponent size ................................ */

    /* setting the pointer to the key database */
    PubKey_ptr = (SaSiRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

    /* calculating the required size in bytes */
    nSizeInBytes = CALC_FULL_BYTES(PubKey_ptr->nSizeInBits);
    eSizeInBytes = CALC_FULL_BYTES(PubKey_ptr->eSizeInBits);

    /* return the modulus size and exit */
    if (Exponent_ptr == NULL && Modulus_ptr == NULL) {
        *ModulusSize_ptr  = (uint16_t)nSizeInBytes;
        *ExponentSize_ptr = (uint16_t)eSizeInBytes;
        return SaSi_OK;
    }
    /* if the size of the modulus is to small return error */
    if (nSizeInBytes > *ModulusSize_ptr)
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    /* if the size of the exponent buffer is to small return error */
    if (eSizeInBytes > *ExponentSize_ptr)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    /* .............. loading the output arguments and buffers ............... */
    /* ----------------------------------------------------------------------- */

    /* loading the buffers */

    Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(Exponent_ptr, 4 * ((*ExponentSize_ptr + 3) / 4), PubKey_ptr->e,
                                                        eSizeInBytes);
    if (Error != SaSi_OK) {
        return Error;
    }

    Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(Modulus_ptr, 4 * ((*ModulusSize_ptr + 3) / 4), PubKey_ptr->n,
                                                        nSizeInBytes);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* updating the buffer sizes */
    *ModulusSize_ptr  = (uint16_t)nSizeInBytes;
    *ExponentSize_ptr = (uint16_t)eSizeInBytes;

End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Modulus_ptr, nSizeInBytes);
        SaSi_PalMemSetZero(Exponent_ptr, eSizeInBytes);
    }

    return SaSi_OK;

} /* END OF SaSi_RSA_Get_PubKey_MTK */

/* *****************************************************************************************

   @brief SaSi_RSA_Get_PrivKeyCRT exports a SaSiRSAPrivKey_t structure data

   @param[In] UserPrivKey_ptr - a pointer to the public key structure. this structure will be used as
                an input to the SaSi_RSA_PRIM_Decrypt_MTK API.

   @param[out] P_ptr - a pointer to the first factor stream of bytes ( Big endian ).
   @param[in/out] PSize_ptr - the size of the first factor buffer in bytes , it is updated to the
          actual size of the first factor, in bytes.
   @param[out] Q_ptr - a pointer to the second factor stream of bytes ( Big endian ).
   @param[in/out] QSize_ptr - the size of the second factor buffer in bytes , it is updated to the
          actual size of the second factor, in bytes.
   @param[out] dP_ptr - a pointer to the first factors CRT exponent stream of bytes ( Big endian ).
   @param[in/out] dPSize_ptr - the size of the first factor exponent buffer in bytes , it is updated to the
          actual size of the first factor exponent, in bytes.
   @param[out] dQ_ptr - a pointer to the second factors CRT exponent stream of bytes ( Big endian ).
   @param[in/out] dQSize_ptr - the size of the second factors CRT exponent buffer in bytes , it is updated to the
          actual size of the second factors CRT exponent, in bytes.
   @param[out] qInv_ptr - a pointer to the first CRT coefficient stream of bytes ( Big endian ).
   @param[in/out] qInvSize_ptr -  the size of the first CRT coefficient buffer in bytes , it is updated to the
          actual size of the first CRT coefficient, in bytes.
*/

CEXPORT_C SaSiError_t SaSi_RSA_Get_PrivKeyCRT(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *P_ptr,
                                              uint16_t *PSize_ptr, uint8_t *Q_ptr, uint16_t *QSize_ptr, uint8_t *dP_ptr,
                                              uint16_t *dPSize_ptr, uint8_t *dQ_ptr, uint16_t *dQSize_ptr,
                                              uint8_t *qInv_ptr, uint16_t *qInvSize_ptr)
{
    /* LOCAL DECLERATIONS */

    /* the size in bytes of the exponents and factors */
    uint32_t PSizeInBytes;
    uint32_t QSizeInBytes;
    uint32_t dPSizeInBytes;
    uint32_t dQSizeInBytes;
    uint32_t qInvSizeInBytes;

    /* the public key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    /* FUNCTION DECLERATIONS */

#ifndef SaSi_NO_HASH_SUPPORT
#ifndef SaSi_NO_PKI_SUPPORT

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* checking the first factor pointer validity */
    if (P_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR;

    /* checking the first factor size pointer validity */
    if (PSize_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_POINTER_ERROR;

    /* checking the second factor pointer validity */
    if (Q_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR;

    /* checking the second factor size pointer validity */
    if (QSize_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_POINTER_ERROR;

    /* checking the first factor exponent pointer validity */
    if (dP_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR;

    /* checking the first factor exponent size pointer validity */
    if (dPSize_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_PTR_ERROR;

    /* checking the second factor exponent pointer validity */
    if (dQ_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR;

    /* checking the second factor exponent size pointer validity */
    if (dQSize_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_PTR_ERROR;

    /* checking the CRT coefficient */
    if (qInv_ptr == NULL)

        return SaSi_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR;

    /* checking the CRT coefficient */
    if (qInvSize_ptr == NULL)
        return SaSi_RSA_INVALID_CRT_COEFFICIENT_SIZE_PTR_ERROR;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* ...... checking the exponent size ................................ */

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    if (PrivKey_ptr->OperationMode != SaSi_RSA_Crt) {
        return SaSi_RSA_WRONG_PRIVATE_KEY_TYPE;
    }

    PSizeInBytes    = (PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits + 7) / 8;
    QSizeInBytes    = (PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits + 7) / 8;
    dPSizeInBytes   = (PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits + 7) / 8;
    dQSizeInBytes   = (PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits + 7) / 8;
    qInvSizeInBytes = (PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits + 7) / 8;

    /* Check that the input buffer are sufficient. */
    if (PSizeInBytes > *PSize_ptr)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_ERROR;

    if (QSizeInBytes > *QSize_ptr)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_ERROR;

    if (dPSizeInBytes > *dPSize_ptr)
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_ERROR;

    if (dQSizeInBytes > *dQSize_ptr)
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_ERROR;

    if (qInvSizeInBytes > *qInvSize_ptr)
        return SaSi_RSA_INVALID_CRT_COEFFICIENT_SIZE_ERROR;

    /* copy the verctors to the buffers. */
    SaSi_COMMON_ReverseMemcpy(P_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.P, PSizeInBytes);

    SaSi_COMMON_ReverseMemcpy(Q_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.Q, QSizeInBytes);

    SaSi_COMMON_ReverseMemcpy(dP_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dP, dPSizeInBytes);

    SaSi_COMMON_ReverseMemcpy(dQ_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dQ, dQSizeInBytes);

    SaSi_COMMON_ReverseMemcpy(qInv_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.qInv, qInvSizeInBytes);

    *PSize_ptr    = (uint16_t)PSizeInBytes;
    *QSize_ptr    = (uint16_t)QSizeInBytes;
    *dPSize_ptr   = (uint16_t)dPSizeInBytes;
    *dQSize_ptr   = (uint16_t)dQSizeInBytes;
    *qInvSize_ptr = (uint16_t)qInvSizeInBytes;

    return SaSi_OK;

#endif /* !SaSi_NO_HASH_SUPPORT */
#endif /* !SaSi_NO_PKI_SUPPORT */

}/* END OF SaSi_RSA_Get_PrivKeyCRT */

CEXPORT_C SaSiError_t SaSi_RSA_Get_PrivKey(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *PrivExponent_ptr,
                                           uint16_t *PrivExponentSize_ptr, uint8_t *PubExponent_ptr,
                                           uint16_t *PubExponentSize_ptr, uint8_t *Modulus_ptr,
                                           uint16_t *ModulusSize_ptr)
{
    /* the size in bytes of the modulus and the exponent */
    uint32_t nSizeInBytes;
    uint32_t dSizeInBytes;
    uint32_t eSizeInBytes;

    /* the public key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;
    SaSiError_t Error;

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the private exponent pointer ............... */
    if (PrivExponent_ptr == NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == NULL)
        return SaSi_RSA_INVALID_MODULUS_POINTER_ERROR;

    if (PrivExponentSize_ptr == NULL)
        return SaSi_RSA_INVALID_EXP_BUFFER_SIZE_POINTER;

    if (ModulusSize_ptr == NULL)
        return SaSi_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* ...... checking the exponent size ................................ */

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    if (PrivKey_ptr->OperationMode != SaSi_RSA_NoCrt) {
        return SaSi_RSA_WRONG_PRIVATE_KEY_TYPE;
    }

    /* calculating the required size in bytes */
    nSizeInBytes = (PrivKey_ptr->nSizeInBits + 7) / 8;
    dSizeInBytes = (PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits + 7) / 8;
    eSizeInBytes = (PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits + 7) / 8;

    /* if the size of the modulous is to small return error */
    if (nSizeInBytes > *ModulusSize_ptr)
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    if (PubExponentSize_ptr != NULL) { /* if the size of the exponent is to small return error */
        if (eSizeInBytes > *PubExponentSize_ptr)
            return SaSi_RSA_INVALID_EXPONENT_SIZE;
    }

    /* if the size of the exponent is to small return error */
    if (dSizeInBytes > *PrivExponentSize_ptr)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    /* loading the the buffers */
    Error = SaSi_COMMON_ReverseMemcpy(Modulus_ptr, (uint8_t *)PrivKey_ptr->n, nSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    if (PubExponent_ptr != NULL) {
        Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(PubExponent_ptr, *PubExponentSize_ptr,
            PrivKey_ptr->PriveKeyDb.NonCrt.e, eSizeInBytes);
        if (Error != SaSi_OK) {
            return Error;
        }
    }

    Error = SaSi_COMMON_ReverseMemcpy(PrivExponent_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.NonCrt.d, dSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    /* updating the buffer sizes */
    *ModulusSize_ptr = (uint16_t)nSizeInBytes;

    if (PubExponentSize_ptr != NULL)
        *PubExponentSize_ptr = (uint16_t)eSizeInBytes;

    *PrivExponentSize_ptr = (uint16_t)dSizeInBytes;

    return SaSi_OK;
}