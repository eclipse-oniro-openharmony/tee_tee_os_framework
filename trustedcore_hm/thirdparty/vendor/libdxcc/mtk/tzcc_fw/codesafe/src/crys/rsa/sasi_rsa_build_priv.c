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
#ifndef DX_OEM_FW
#include "sasi.h"
#else
#include "oem_sasi.h"
#endif
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_rsa_error.h"
#include "sasi_rsa_local.h"

/* .............. LLF level includes ................. */

#include "llf_pki_rsa.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */


/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Public Functions **************************** */

#if !defined(_INTERNAL_SaSi_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_SIGN_SUPPORT)
/* *****************************************************************************************
   @brief SaSi_RSA_Get_PrivKey gets the D,e,n of private key from the database.

   @param[in] UserPrivKey_ptr - A pointer to the private key structure.
                   This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.

   @param[out] PrivExponent_ptr - A pointer to the exponent stream of bytes (Big-Endian format)

   @param[in/out] PrivExponentSize - the size of the exponent buffer in bytes , it is updated to the
          actual size of the exponent, in bytes.

   @param[out] PubExponent_ptr - a pointer to the public exponent stream of bytes ( Big endian ).

   @param[in/out] PubExponentSize - the size of the exponent buffer in bytes , it is updated to the
          actual size of the exponent, in bytes.

   @param[out] Modulus_ptr  - A pointer to the modulus stream of bytes (Big-Endian format).
               The MS (most significant) bit must be set to '1'.

   @param[in/out] ModulusSize_ptr  - the size of the modulus buffer in bytes , it is updated to the
          actual size of the modulus, in bytes.
*/
CEXPORT_C SaSiError_t SaSi_RSA_Get_PrivKey(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *PrivExponent_ptr,
                                           uint16_t *PrivExponentSize_ptr, uint8_t *PubExponent_ptr,
                                           uint16_t *PubExponentSize_ptr, uint8_t *Modulus_ptr,
                                           uint16_t *ModulusSize_ptr)
{
    /* LOCAL DECLERATIONS */

    /* the size in bytes of the modulus and the exponent */
    uint32_t nSizeInBytes;
    uint32_t dSizeInBytes;
    uint32_t eSizeInBytes;

    /* the public key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    SaSiError_t Error;

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

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
    nSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->nSizeInBits);
    dSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits);
    eSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits);

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

    /* .............. loading the output arguments and buffers ............... */
    /* ----------------------------------------------------------------------- */

    /* loading the the buffers */
    Error = SaSi_COMMON_ReverseMemcpy(Modulus_ptr, (uint8_t *)PrivKey_ptr->n, nSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    if (PubExponent_ptr != NULL) {
        SaSi_COMMON_LsMsWordsArrayToMsLsBytes(PubExponent_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.NonCrt.e,
                                              eSizeInBytes);
    }

    Error = SaSi_COMMON_ReverseMemcpy(PrivExponent_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.NonCrt.d, dSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    /* updating the buffer sizes */
    *ModulusSize_ptr = (uint16_t)nSizeInBytes;

    if (PubExponentSize_ptr != NULL) {
        *PubExponentSize_ptr = (uint16_t)eSizeInBytes;
    }

    *PrivExponentSize_ptr = (uint16_t)dSizeInBytes;

    return SaSi_OK;

} /* END OF SaSi_RSA_Get_PrivKey */

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

    SaSiError_t Error;

    /* FUNCTION DECLERATIONS */
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

    PSizeInBytes    = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits);
    QSizeInBytes    = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits);
    dPSizeInBytes   = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits);
    dQSizeInBytes   = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits);
    qInvSizeInBytes = CALC_FULL_BYTES(PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits);

    /* Check that the input buffer are sufficient. */
    if (PSizeInBytes > *PSize_ptr) {
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_ERROR;
    }

    if (QSizeInBytes > *QSize_ptr) {
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_ERROR;
    }

    if (dPSizeInBytes > *dPSize_ptr) {
        return SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_ERROR;
    }

    if (dQSizeInBytes > *dQSize_ptr) {
        return SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_ERROR;
    }

    if (qInvSizeInBytes > *qInvSize_ptr) {
        return SaSi_RSA_INVALID_CRT_COEFFICIENT_SIZE_ERROR;
    }

    /* copy the verctors to the buffers. */
    Error = SaSi_COMMON_ReverseMemcpy(P_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.P, PSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    Error = SaSi_COMMON_ReverseMemcpy(Q_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.Q, QSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    Error = SaSi_COMMON_ReverseMemcpy(dP_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dP, dPSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    Error = SaSi_COMMON_ReverseMemcpy(dQ_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dQ, dQSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    Error = SaSi_COMMON_ReverseMemcpy(qInv_ptr, (uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.qInv, qInvSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    *PSize_ptr    = (uint16_t)PSizeInBytes;
    *QSize_ptr    = (uint16_t)QSizeInBytes;
    *dPSize_ptr   = (uint16_t)dPSizeInBytes;
    *dQSize_ptr   = (uint16_t)dQSizeInBytes;
    *qInvSize_ptr = (uint16_t)qInvSizeInBytes;

    return SaSi_OK;

} /* END OF SaSi_RSA_Get_PrivKeyCRT */

/* *****************************************************************************************

   @brief SaSi_RSA_Get_PrivKeyModulus export the modulus vector from SaSiRSAPrivKey_t structure.

   @param[out] UserPrivKey_ptr - a pointer to the private key structure.

   @param[out] N_ptr - a pointer to the modulus vector of bytes ( Big endian ).
   @param[in/out] NSize_ptr - the size of the modulus buffer in bytes , it is updated to the
          actual size in bytes.
*/

CEXPORT_C SaSiError_t SaSi_RSA_Get_PrivKeyModulus(SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, uint8_t *N_ptr,
                                                  uint16_t *NSize_ptr)
{
    /* LOCAL DECLERATIONS */

    /* the size in bytes of the exponents and factors */
    uint32_t NSizeInBytes;

    /* the public key database pointer */
    SaSiRSAPrivKey_t *PrivKey_ptr;

    SaSiError_t Error;

    /* FUNCTION DECLERATIONS */
    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

    /* ...... checking the key database handle pointer .................... */
    if (UserPrivKey_ptr == NULL)

        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* checking the first factor pointer validity */
    if (N_ptr == NULL)

        return SaSi_RSA_INVALID_MODULUS_POINTER_ERROR;

    /* checking the first factor size pointer validity */
    if (NSize_ptr == NULL)

        return SaSi_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;

    /* if the users TAG is illegal return an error - the context is invalid */
    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)

        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* ...... checking the exponent size ................................ */

    /* setting the pointer to the key database */
    PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    NSizeInBytes = PrivKey_ptr->nSizeInBits / 8;

    if (PrivKey_ptr->nSizeInBits % 8) {
        NSizeInBytes++;
    }

    /* Check that the input buffer is sufficient */
    if (NSizeInBytes > *NSize_ptr) {
        return SaSi_RSA_INVALID_EXPONENT_SIZE;
    }

    /* copy the verctor to the buffer */
    Error = SaSi_COMMON_ReverseMemcpy(N_ptr, (uint8_t *)PrivKey_ptr->n, NSizeInBytes);
    if (Error != SaSi_OK)
        return Error;

    *NSize_ptr = (uint16_t)NSizeInBytes;

    return SaSi_OK;

} /* END OF SaSi_RSA_Get_PrivKeyCRT */

#endif /* !defined(_INTERNAL_SaSi_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_SaSi_NO_RSA_SIGN_SUPPORT) */
