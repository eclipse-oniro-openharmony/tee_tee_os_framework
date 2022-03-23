/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: rsa build
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "drv_osal_lib.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_rsa_error.h"
#include "crys_rsa_types.h"
#include "crys_rsa_build.h"
#include "crys_rsa_local.h"
#include "crys_rsa_schemes.h"
#include "crys_common_math.h"
#include "crys_rsa_kg.h"
#include "crys_rnd.h"
#include "crys_cipher_common.h"
#include "crys_common.h"

/* *********************** Defines ***************************** */
/*  canceling the lint warning:
   Use of goto is deprecated  */
/* lint --e{801}  */
#define NUM_2 2
#define NUM_3 3
#define NUM_4 4
#define OFFSET_3  3
#define OFFSET_7  7
#define OFFSET_31 31
#define BYTE_BIT_WIDTH 8

#if !defined(_INTERNAL_CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT)

/******************************************************************************************/
/**
 * @brief CRYS_RSA_Build_PubKey populates a CRYSRSAPubKey_t structure with
 *       the provided modulus and exponent.
 *
 *    Assumption : the modulus and the exponent are presented in big endian.
 *
 * @param[out] pub_key - a pointer to the public key structure. This structure will be
 *            used as an input to the CRYS_RSA_PRIM_Encrypt API.
 *
 * @param[in] Exponent_ptr - a pointer to the exponent stream of bytes (Big endian).
 * @param[in] exponent_size - The size of the exponent in bytes.
 * @param[in] Modulus_ptr  - a pointer to the modulus stream of bytes (Big endian) the MS
 *           bit must be set to '1'.
 * @param[in] modulus_size  - The size of the modulus in bytes. Sizes supported according to
 *           used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CEXPORT_C CRYSError_t __CRYS_RSA_Build_PubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                              DxUint8_t *Exponent_ptr,
                                              DxUint16_t exponent_size,
                                              DxUint8_t *Modulus_ptr,
                                              DxUint16_t modulus_size)
{
    CRYS_COMMON_CmpCounter_t counter_cmp_result;
    DxUint32_t modulus_effective_size_in_bits;
    DxUint32_t exponent_effective_size_in_bits;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    CRYSError_t error;
    DxUint32_t buffer_size = CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES;

    /* ...... checking the key database handle pointer .................... */
    if (Userpub_key == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the exponent pointer ............... */
    if (Exponent_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;
    }

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_MODULUS_POINTER_ERROR;
    }

    if (modulus_size > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    if (exponent_size > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /* setting the pointer to the key database */
    pub_key = (CRYSRSAPubKey_t *)Userpub_key->PublicKeyDbBuff;

    /* clear the public key db */
    error = memset_s(pub_key, sizeof(CRYSRSAPubKey_t), 0, sizeof(CRYSRSAPubKey_t));
    if (error != HI_SUCCESS) {
        return error;
    }

    /* loading the buffers to little endian order of words in array; each word is
       loaded according to CPU endianness */
    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pub_key->n, buffer_size, Modulus_ptr, modulus_size);
    if (error) {
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pub_key->e, buffer_size, Exponent_ptr, exponent_size);
    if (error) {
        return error;
    }

    /*  .......... initializing the effective counters size in bits ..........  */
    modulus_effective_size_in_bits = CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pub_key->n,
        (modulus_size + OFFSET_3) / NUM_4);
    exponent_effective_size_in_bits = CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pub_key->e,
        (exponent_size + OFFSET_3) / NUM_4);

    /* .................. checking the validity of the counters ............... */
    /* ------------------------------------------------------------------------ */
    if ((modulus_effective_size_in_bits < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (modulus_effective_size_in_bits > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        hi_log_error("Invalid input, modulus_effective_size_in_bits[0x%x]\n", modulus_effective_size_in_bits);
        error = CRYS_RSA_INVALID_MODULUS_SIZE;
        goto End;
    }
    /* verifying the modulus is odd */
    if ((pub_key->n[0] & 1UL) == 0) {
        error = CRYS_RSA_MODULUS_EVEN_ERROR;
        goto End;
    }

    /* checking the exponent size is not 0 in bytes */
    if (exponent_effective_size_in_bits == 0) {
        error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifying the exponent is less then the modulus */
    counter_cmp_result = CRYS_COMMON_CmpMsbUnsignedCounters(Exponent_ptr, exponent_size, Modulus_ptr, modulus_size);
    if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
        error = CRYS_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /*   verifying the exponent is not less then 3  */
    if (exponent_effective_size_in_bits < WORD_BIT_WIDTH && pub_key->e[0] < CRYS_RSA_MIN_PUB_EXP_VALUE) {
        error = CRYS_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* setting the modulus and exponent size in bits */
    pub_key->nSizeInBits = modulus_effective_size_in_bits;
    pub_key->eSizeInBits = exponent_effective_size_in_bits;

    /* ................ set the tag ................ */
    Userpub_key->valid_tag = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

End:
    /* if the structure created is not valid - clear it */
    if (error != CRYS_OK) {
        (void)memset_s(Userpub_key, sizeof(CRYS_RSAUserPubKey_t), 0, sizeof(CRYS_RSAUserPubKey_t));
    }

    return error;
} /* END OF CRYS_RSA_Build_PubKey */

CEXPORT_C CRYSError_t CRYS_RSA_Build_PubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                            DxUint8_t *Exponent_ptr,
                                            DxUint16_t exponent_size,
                                            DxUint8_t *Modulus_ptr,
                                            DxUint16_t modulus_size)
{
    DxUint8_t *exponent = HI_NULL;
    DxUint8_t *modulus = HI_NULL;
    CRYSError_t error;

    exponent = (DxUint8_t *)crypto_malloc(exponent_size);
    if (exponent == HI_NULL) {
        hi_log_error("malloc for exponent falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memcpy_s(exponent, exponent_size, Exponent_ptr, exponent_size);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    modulus = (DxUint8_t *)crypto_malloc(modulus_size);
    if (modulus == HI_NULL) {
        hi_log_error("malloc for modulus falied\n");
        goto err;
    }

    error = memcpy_s(modulus, modulus_size, Modulus_ptr, modulus_size);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = __CRYS_RSA_Build_PubKey(Userpub_key, exponent, exponent_size, modulus, modulus_size);
    if (error != CRYS_OK) {
        hi_log_print_func_err(__CRYS_RSA_Build_PubKey, error);
        goto err;
    }
err:
    if (exponent != HI_NULL) {
        crypto_free(exponent);
        exponent = HI_NULL;
    }
    if (modulus != HI_NULL) {
        crypto_free(modulus);
        modulus = HI_NULL;
    }

    return error;
}
#endif /* !defined(_INTERNAL_CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT) */

/******************************************************************************************/
/**
 * @brief CRYS_RSA_Build_PrivKey populates a CRYSRSAPrivKey_t structure with
 *        the provided modulus and exponent, marking the key as a "non-CRT" key.
 *
 *        Assumption : the modulus and the exponent are presented in big endian.
 *
 * @param[out] Userprivate_key - a pointer to the public key structure. this structure will be used as
 *                          an input to the CRYS_RSA_PRIM_Decrypt API.
 * @param[in] PrivExponent_ptr - a pointer to the private exponent stream of bytes (Big endian).
 * @param[in] Privexponent_size - the size of the private exponent in bytes.
 * @param[in] Exponent_ptr - a pointer to the exponent stream of bytes (Big endian).
 * @param[in] exponent_size - the size of the exponent in bytes.
 * @param[in] Modulus_ptr  - a pointer to the modulus stream of bytes (Big endian) the MS
 *            bit must be set to '1'.
 * @param[in] modulus_size  - the size of the modulus in bytes. Sizes supported according to
 *            used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                       value MODULE_* as defined in ...
 *
 */
CEXPORT_C CRYSError_t __CRYS_RSA_Build_PrivKey(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                               DxUint8_t *PrivExponent_ptr,
                                               DxUint16_t Privexponent_size,
                                               DxUint8_t *PubExponent_ptr,
                                               DxUint16_t Pubexponent_size,
                                               DxUint8_t *Modulus_ptr,
                                               DxUint16_t modulus_size)
{
    CRYS_COMMON_CmpCounter_t counter_cmp_result;
    DxUint32_t modulus_effective_size_in_bits;
    DxUint32_t private_exponent_effective_bits;
    DxUint32_t public_exponent_effective_bits;
    CRYSRSAPrivKey_t *private_key = HI_NULL;
    DxUint32_t buffer_size = CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES;
    CRYSError_t error;

    /* ...... checking the key database handle pointer .................... */
    if (Userprivate_key == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the exponents pointers ........... */
    if (PrivExponent_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;
    }

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_MODULUS_POINTER_ERROR;
    }

    /* checking the validity of the modulus size, private exponent can not be more than 256 bytes */
    if (modulus_size > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES) {
        hi_log_error("Invalid input, modulus_size[0x%x]\n", modulus_size);
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    if (Privexponent_size > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / BYTE_BIT_WIDTH) {
        hi_log_error("Invalid input, Privexponent_size[0x%x]\n", Privexponent_size);
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    if (PubExponent_ptr != DX_NULL &&
        Pubexponent_size > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES) {
        hi_log_error("Invalid input, Pubexponent_size[0x%x]\n", Pubexponent_size);
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /* setting the pointer to the key database */
    private_key = (CRYSRSAPrivKey_t *)Userprivate_key->PrivateKeyDbBuff;

    /* clear the private key db */
    error = memset_s(private_key, sizeof(CRYSRSAPrivKey_t), 0, sizeof(CRYSRSAPrivKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        return error;
    }

    /* loading the buffers to little endian order of words in array; each word is loaded according to CPU endianness */
    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->n, buffer_size, Modulus_ptr, modulus_size);
    if (error != CRYS_OK) {
        hi_log_error("Error[0x%x]\n", error);
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.NonCrt.d, buffer_size,
                                                        PrivExponent_ptr, Privexponent_size);
    if (error != CRYS_OK) {
        hi_log_error("Error[0x%x]\n", error);
        return error;
    }

    /* get actual sizes of modulus and private exponent */
    modulus_effective_size_in_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->n, (modulus_size + OFFSET_3) / NUM_4);

    private_exponent_effective_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.NonCrt.d,
                                                       (Privexponent_size + OFFSET_3) / NUM_4);

    /* checking the size of the modulus */
    if ((modulus_effective_size_in_bits < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (modulus_effective_size_in_bits > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        error = CRYS_RSA_INVALID_MODULUS_SIZE;
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* verifying the modulus is odd */
    if ((private_key->n[0] & 1UL) == 0) {
        error = CRYS_RSA_MODULUS_EVEN_ERROR;
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* checking the priv. exponent size is not 0 in bytes */
    if (private_exponent_effective_bits == 0) {
        error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* verifying the priv. exponent is less then the modulus */
    counter_cmp_result = CRYS_COMMON_CmpMsbUnsignedCounters(PrivExponent_ptr, Privexponent_size,
                                                            Modulus_ptr, modulus_size);
    if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
        error = CRYS_RSA_INVALID_EXPONENT_VAL;
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* verifying the priv. exponent is not less then 1 */
    if (private_exponent_effective_bits < 32 && /* 32 : max bits */
        private_key->PriveKeyDb.NonCrt.d[0] < CRYS_RSA_MIN_PRIV_EXP_VALUE) {
        error = CRYS_RSA_INVALID_EXPONENT_VAL;
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* checking that the public exponent is an integer between 3 and modulus - 1 */
    if (PubExponent_ptr != DX_NULL) {
        /* loading the buffer to little endian order of words in array; each word is
           loaded according to CPU endianness */
        error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.NonCrt.e, buffer_size,
                                                            PubExponent_ptr, Pubexponent_size);
        if (error) {
            hi_log_error("Error[0x%x]\n", error);
            return error;
        }

        public_exponent_effective_bits =
            CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.NonCrt.e,
                (Pubexponent_size + OFFSET_3) / NUM_4);
        if (public_exponent_effective_bits < 32 && /* verifying that the exponent is not less than 32 */
            private_key->PriveKeyDb.NonCrt.e[0] < CRYS_RSA_MIN_PUB_EXP_VALUE) {
            error = CRYS_RSA_INVALID_EXPONENT_VAL;
            hi_log_error("Error[0x%x]\n", error);
            goto End;
        }

        /* verifying that the public exponent is less than the modulus */
        counter_cmp_result = CRYS_COMMON_CmpMsbUnsignedCounters(PubExponent_ptr, Pubexponent_size,
                                                                Modulus_ptr, modulus_size);
        if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
            error = CRYS_RSA_INVALID_EXPONENT_VAL;
            hi_log_error("Error[0x%x]\n", error);
            goto End;
        }
    } else {
        public_exponent_effective_bits = 0;
    }

    /* set the mode to non CRT mode */
    private_key->OperationMode = CRYS_RSA_NoCrt;

    /* set the key source as external */
    private_key->KeySource = CRYS_RSA_ExternalKey;

    /* setting the modulus and exponent size in bits */
    private_key->nSizeInBits = modulus_effective_size_in_bits;
    private_key->PriveKeyDb.NonCrt.dSizeInBits = private_exponent_effective_bits;
    private_key->PriveKeyDb.NonCrt.eSizeInBits = public_exponent_effective_bits;

    if (error) {
        hi_log_error("Error[0x%x]\n", error);
        goto End;
    }

    /* ................ set the tag ................ */
    Userprivate_key->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
End:
    /* if the structure created is not valid - clear it */
    if (error) {
        (void)memset_s(Userprivate_key, sizeof(CRYS_RSAUserPrivKey_t), 0, sizeof(CRYS_RSAUserPrivKey_t));
    }

    return error;
} /* END OF CRYS_RSA_Build_PrivKey */

CEXPORT_C CRYSError_t CRYS_RSA_Build_PrivKey(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                             DxUint8_t *PrivExponent_ptr,
                                             DxUint16_t Privexponent_size,
                                             DxUint8_t *PubExponent_ptr,
                                             DxUint16_t Pubexponent_size,
                                             DxUint8_t *Modulus_ptr,
                                             DxUint16_t modulus_size)
{
    DxUint8_t *private_exponen = HI_NULL;
    DxUint8_t *pub_exponent = HI_NULL;
    DxUint8_t *modulus = HI_NULL;
    CRYSError_t error = CRYS_FATAL_ERROR;

    if ((Userprivate_key == HI_NULL) || (PrivExponent_ptr == HI_NULL) || (PubExponent_ptr == HI_NULL) ||
        (Modulus_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    private_exponen = (DxUint8_t *)crypto_malloc(Privexponent_size);
    if (private_exponen == HI_NULL) {
        hi_log_error("malloc for private_exponen falied\n");
        goto err;
    }
    error = memcpy_s(private_exponen, Privexponent_size, PrivExponent_ptr, Privexponent_size);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    pub_exponent = (DxUint8_t *)crypto_malloc(Pubexponent_size);
    if (pub_exponent == HI_NULL) {
        hi_log_error("malloc for pub_exponent falied\n");
        goto err;
    }
    error = memcpy_s(pub_exponent, Pubexponent_size, PubExponent_ptr, Pubexponent_size);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    modulus = (DxUint8_t *)crypto_malloc(modulus_size);
    if (modulus == HI_NULL) {
        hi_log_error("malloc for modulus falied\n");
        goto err;
    }
    error = memcpy_s(modulus, modulus_size, Modulus_ptr, modulus_size);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = __CRYS_RSA_Build_PrivKey(Userprivate_key, private_exponen, Privexponent_size,
                                     pub_exponent, Pubexponent_size, modulus, modulus_size);
    if (error != CRYS_OK) {
        hi_log_print_func_err(__CRYS_RSA_Build_PrivKey, error);
        goto err;
    }

err:
    if (private_exponen != HI_NULL) {
        crypto_free(private_exponen);
        private_exponen = HI_NULL;
    }
    if (pub_exponent != HI_NULL) {
        crypto_free(pub_exponent);
        pub_exponent = HI_NULL;
    }
    if (modulus != HI_NULL) {
        crypto_free(modulus);
        modulus = HI_NULL;
    }

    return error;
}

/******************************************************************************************

   @brief CRYS_RSA_Build_PrivKeyCRT populates a CRYSRSAPrivKey_t structure with
          the provided parameters, marking the key as a "CRT" key.

    Note: The "First" factor P must be great, than the "Second" factor Q.


   @param[out] Userprivate_key - A pointer to the public key structure.
                    This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
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
CEXPORT_C CRYSError_t CRYS_RSA_Build_PrivKeyCRT(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                                DxUint8_t *P_ptr,
                                                DxUint16_t PSize,
                                                DxUint8_t *Q_ptr,
                                                DxUint16_t QSize,
                                                DxUint8_t *dP_ptr,
                                                DxUint16_t dPSize,
                                                DxUint8_t *dQ_ptr,
                                                DxUint16_t dQSize,
                                                DxUint8_t *qInv_ptr,
                                                DxUint16_t qInvSize)
{
    CRYS_COMMON_CmpCounter_t counter_cmp_result;
    DxUint32_t p_bits;
    DxUint32_t q_bits;
    DxUint32_t dp_bits;
    DxUint32_t dq_bits;
    DxUint32_t qp_bits;
    DxUint32_t modulus_effective_size_in_bits;
    CRYSRSAPrivKey_t *private_key = HI_NULL;
    DxUint32_t buffer_size = WORD_WIDTH * ((PSize + OFFSET_3) / WORD_WIDTH) + WORD_WIDTH;
    CRYSError_t error;
    hi_u8 *n = HI_NULL;
    hi_s32 ret;

    /* ...... checking the key database handle pointer .................... */
    if (Userprivate_key == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* checking the first factor pointer validity */
    if (P_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR;
    }

    /* checking the second factor pointer validity */
    if (Q_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR;
    }

    /* checking the first factor exponent pointer validity */
    if (dP_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR;
    }

    /* checking the second factor exponent pointer validity */
    if (dQ_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR;
    }

    /* checking the CRT coefficient */
    if (qInv_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR;
    }

    /* checking the input sizes */
    if (dPSize > PSize ||
        dQSize > QSize ||
        qInvSize > PSize) {
        return CRYS_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
    }

    /* verifying the first factor exponent is less then the first factor */
    counter_cmp_result =
        CRYS_COMMON_CmpMsbUnsignedCounters(dP_ptr, dPSize, P_ptr, PSize);
    if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
        error = CRYS_RSA_INVALID_CRT_FIRST_FACTOR_EXPONENT_VAL;
        goto End;
    }
    /*  verifying the second factor exponent is less then the second factor  */
    counter_cmp_result =
        CRYS_COMMON_CmpMsbUnsignedCounters(dQ_ptr, dQSize, Q_ptr, QSize);
    if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
        error = CRYS_RSA_INVALID_CRT_SECOND_FACTOR_EXPONENT_VAL;
        goto End;
    }

    /*  verifying the CRT coefficient is less then the first factor  */
    counter_cmp_result =
        CRYS_COMMON_CmpMsbUnsignedCounters(qInv_ptr, qInvSize, P_ptr, PSize);
    if (counter_cmp_result != CRYS_COMMON_CmpCounter2GraterThenCounter1) {
        error = CRYS_RSA_INVALID_CRT_COEFF_VAL;
        goto End;
    }

    /*  setting the pointer to the key database  */
    private_key = (CRYSRSAPrivKey_t *)Userprivate_key->PrivateKeyDbBuff;
    /*  clear the private key db  */
    ret = memset_s(private_key, sizeof(CRYSRSAPrivKey_t),
                   0, sizeof(CRYSRSAPrivKey_t));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    n = (hi_u8 *)private_key->n;
    n += sizeof(private_key->n);
    if (crys_ras_call_mul(n, P_ptr, Q_ptr, NUM_2 * PSize, PSize, QSize) != HI_SUCCESS) {
        error = CRYS_FATAL_ERROR;
        goto End;
    }
    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->n, WORD_WIDTH *
                                                        ((NUM_2 * PSize + NUM_3) / WORD_WIDTH) + WORD_WIDTH,
                                                        n, NUM_2 * PSize);
    if (error) {
        return error;
    }

    /* load the buffers to the data base */
    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.Crt.P, buffer_size, P_ptr, PSize);
    if (error) {
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.Crt.Q, buffer_size, Q_ptr, QSize);
    if (error) {
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.Crt.dP, buffer_size, dP_ptr, dPSize);
    if (error) {
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.Crt.dQ, buffer_size, dQ_ptr, dQSize);
    if (error) {
        return error;
    }

    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(private_key->PriveKeyDb.Crt.qInv, buffer_size, qInv_ptr,
                                                        qInvSize);
    if (error) {
        return error;
    }

    /* initializing the effective counters size in bits */
    p_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.Crt.P,
                                                       (PSize + OFFSET_3) / WORD_WIDTH);

    q_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.Crt.Q,
                                                       (QSize + OFFSET_3) / WORD_WIDTH);

    dp_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.Crt.dP,
                                                       (dPSize + OFFSET_3) / WORD_WIDTH);

    dq_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.Crt.dQ,
                                                       (dQSize + OFFSET_3) / WORD_WIDTH);

    qp_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->PriveKeyDb.Crt.qInv,
                                                       (qInvSize + OFFSET_3) / WORD_WIDTH);

    /* the first factor size is not 0 in bits */
    if (p_bits == 0) {
        error = CRYS_RSA_INVALID_CRT_FIRST_FACTOR_SIZE;
        goto End;
    }

    /* the second factor size is not 0 in bits */
    if (q_bits == 0) {
        error = CRYS_RSA_INVALID_CRT_SECOND_FACTOR_SIZE;
        goto End;
    }

    /* checking that sizes of dP, dQ, qInv > 0 */
    if (dp_bits == 0 || dq_bits == 0 || qp_bits == 0) {
        error = CRYS_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;
        goto End;
    }

    /*  ............... calculate the modulus N ...........................  */
    /*  --------------------------------------------------------------------  */
    if (sizeof(private_key->n) <
        (((NUM_2 * p_bits + OFFSET_31) / WORD_BIT_WIDTH) * sizeof(DxUint32_t))) {
        error = CRYS_RSA_INVALID_CRT_SECOND_FACTOR_SIZE;
        goto End;
    }

    modulus_effective_size_in_bits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(private_key->n,
                                                       (NUM_2 * p_bits + OFFSET_31) / WORD_BIT_WIDTH);
    /*  the size of the modulus   */
    if ((modulus_effective_size_in_bits < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (modulus_effective_size_in_bits > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        error = CRYS_RSA_INVALID_MODULUS_SIZE;
        goto End;
    }

    if ((p_bits + q_bits != modulus_effective_size_in_bits) &&
        (p_bits + q_bits != modulus_effective_size_in_bits - 1)) {
        error = CRYS_RSA_INVALID_CRT_FIRST_AND_SECOND_FACTOR_SIZE;
        goto End;
    }

    /*  set the mode to CRT mode  */
    private_key->OperationMode = CRYS_RSA_Crt;

    /*  set the key source as external  */
    private_key->KeySource = CRYS_RSA_ExternalKey;

    /*  loading to structure the buffer sizes...  */
    private_key->PriveKeyDb.Crt.PSizeInBits = p_bits;
    private_key->PriveKeyDb.Crt.QSizeInBits = q_bits;
    private_key->PriveKeyDb.Crt.dPSizeInBits = dp_bits;
    private_key->PriveKeyDb.Crt.dQSizeInBits = dq_bits;
    private_key->PriveKeyDb.Crt.qInvSizeInBits = qp_bits;
    private_key->nSizeInBits = modulus_effective_size_in_bits;

    /*  ................ set the tag ................  */
    Userprivate_key->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
End:
    /*  if the structure created is not valid - clear it  */
    if (error) {
        ret = memset_s(Userprivate_key, sizeof(CRYS_RSAUserPrivKey_t),
                       0, sizeof(CRYS_RSAUserPrivKey_t));
        if (ret != HI_SUCCESS) {
            return ret;
        }
    }

    return error;
} /* END OF CRYS_RSA_Build_PrivKeyCRT */

CEXPORT_C CRYSError_t CRYS_RSA_Build_ConvertPrivKeyToCRT(CRYS_RSAUserPrivKey_t *Userprivate_key,
                                                         CRYS_RSAConvertKeyToCrtBuffers_t *Buffers_ptr)
{
    hi_log_error("CRYS_RSA_Build_ConvertPrivKeyToCRT not suppot!\n");
    return CRYS_FATAL_ERROR;
}

/******************************************************************************************
   @brief CRYS_RSA_Get_PubKey gets the e,n public key from the database.

   @param[in] Userpub_key - A pointer to the public key structure.
                               This structure is used as input to the CRYS_RSA_PRIM_Encrypt API.

   @param[out] Exponent_ptr - A pointer to the exponent stream of bytes (Big-Endian format)
   @param[in,out] exponent_size_ptr - the size of the exponent buffer in bytes, it is updated to the
                  actual size of the exponent, in bytes.
   @param[out] Modulus_ptr  - A pointer to the modulus stream of bytes (Big-Endian format).
               The MS (most significant) bit must be set to '1'.
   @param[in,out] modulus_size_ptr  - the size of the modulus buffer in bytes, it is updated to the
                  actual size of the modulus, in bytes.

   NOTE: All members of input UserPrivKey structure must be initialized, including public key
         e pointer and it size.

 */
CEXPORT_C CRYSError_t __CRYS_RSA_Get_PubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                            DxUint8_t *Exponent_ptr,
                                            DxUint16_t *exponent_size_ptr,
                                            DxUint8_t *Modulus_ptr,
                                            DxUint16_t *modulus_size_ptr)
{
    DxUint32_t n_size_in_bytes;
    DxUint32_t e_size_in_bytes;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    CRYSError_t error;

    /* ...... checking the key database handle pointer .................... */
    if (Userpub_key == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the exponent pointer ............... */
    if (Exponent_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;
    }

    /* ...... checking the validity of the modulus pointer .............. */
    if (Modulus_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_MODULUS_POINTER_ERROR;
    }

    if (exponent_size_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXP_BUFFER_SIZE_POINTER;
    }

    if (modulus_size_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;
    }

    /* if the users TAG is illegal return an error - the context is invalid */
    if (Userpub_key->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PUB_KEY_VALIDATION_TAG_ERROR;
    }

    /* setting the pointer to the key database */
    pub_key = (CRYSRSAPubKey_t *)Userpub_key->PublicKeyDbBuff;

    /*  calculating the required size in bytes  */
    n_size_in_bytes = (pub_key->nSizeInBits + OFFSET_7) / BYTE_BIT_WIDTH;
    e_size_in_bytes = (pub_key->eSizeInBits + OFFSET_7) / BYTE_BIT_WIDTH;

    /* if the size of the modulus is to small return error */
    if (n_size_in_bytes > *modulus_size_ptr) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    /* if the size of the exponent buffer is to small return error */
    if (e_size_in_bytes > *exponent_size_ptr) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /*  loading the buffers  */
    error = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(Exponent_ptr,
                                                        WORD_WIDTH * ((*exponent_size_ptr + OFFSET_3) / WORD_WIDTH),
                                                        pub_key->e, e_size_in_bytes);
    if (error != CRYS_OK) {
        return error;
    }

    error = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(Modulus_ptr,
                                                        WORD_WIDTH * ((*modulus_size_ptr + OFFSET_3) / WORD_WIDTH),
                                                        pub_key->n, n_size_in_bytes);
    if (error != CRYS_OK) {
        return error;
    }

    /* updating the buffer sizes */
    *modulus_size_ptr = (DxUint16_t)n_size_in_bytes;
    *exponent_size_ptr = (DxUint16_t)e_size_in_bytes;

    return CRYS_OK;
} /* END OF CRYS_RSA_Get_PubKey */

CEXPORT_C CRYSError_t CRYS_RSA_Get_PubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                          DxUint8_t *Exponent_ptr,
                                          DxUint16_t *exponent_size_ptr,
                                          DxUint8_t *Modulus_ptr,
                                          DxUint16_t *modulus_size_ptr)
{
    CRYS_RSAUserPubKey_t *user_pub_key = HI_NULL;
    DxUint16_t exponent_size;
    DxUint16_t modulus_size;
    CRYSError_t error;

    if ((Userpub_key == HI_NULL) || (Exponent_ptr == HI_NULL) || (exponent_size_ptr == HI_NULL) ||
        (Modulus_ptr == HI_NULL) || (modulus_size_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    exponent_size = *exponent_size_ptr;
    modulus_size = *modulus_size_ptr;

    user_pub_key = (CRYS_RSAUserPubKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPubKey_t));
    if (user_pub_key == HI_NULL) {
        hi_log_error("malloc for user_pub_key falied\n");
        return CRYS_FATAL_ERROR;
    }

    error = memcpy_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), Userpub_key, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto End;
    }

    error = __CRYS_RSA_Get_PubKey(user_pub_key, Exponent_ptr, &exponent_size, Modulus_ptr, &modulus_size);
    if (error == CRYS_OK) {
        *exponent_size_ptr = exponent_size;
        *modulus_size_ptr = modulus_size;
    }
End:
    if (user_pub_key != HI_NULL) {
        crypto_free(user_pub_key);
        user_pub_key = HI_NULL;
    }

    return error;
}

/******************************************************************************************
   @brief CRYS_RSA_Get_ModSizeFromPubKey extracts the modulus size from a given public key data structure.

   @param[in] Userpub_key - A pointer to the public key structure, as returned by
                               CRYS_RSA_Build_PubKey.

   @param[out] modulus_size_ptr  -  The actual size of the modulus, in bytes.
 */
CEXPORT_C CRYSError_t __CRYS_RSA_Get_ModSizeFromPubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                                       DxUint16_t *modulus_size_ptr)
{
    CRYSRSAPubKey_t *pub_key = HI_NULL;

    /* ...... checking the key database handle pointer .................... */
    if (Userpub_key == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* checking the modulus size output pointer validity */
    if (modulus_size_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;
    }

    /* if the users TAG is illegal return an error - the context is invalid */
    if (Userpub_key->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG) {
        return CRYS_RSA_PUB_KEY_VALIDATION_TAG_ERROR;
    }

    /* setting the pointer to the key database */
    pub_key = (CRYSRSAPubKey_t *)Userpub_key->PublicKeyDbBuff;

    /*  calculating the required size in bytes  */
    *modulus_size_ptr = (DxUint16_t)((pub_key->nSizeInBits + OFFSET_7) / BYTE_BIT_WIDTH);

    return CRYS_OK;
} /* END OF CRYS_RSA_Get_ModSizeFromPubKey */

CEXPORT_C CRYSError_t CRYS_RSA_Get_ModSizeFromPubKey(CRYS_RSAUserPubKey_t *Userpub_key,
                                                     DxUint16_t *modulus_size_ptr)
{
    CRYS_RSAUserPubKey_t *user_pub_key = HI_NULL;
    CRYSError_t error;

    if ((Userpub_key == HI_NULL) || (modulus_size_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    user_pub_key = (CRYS_RSAUserPubKey_t *)crypto_malloc(sizeof(CRYS_RSAUserPubKey_t));
    if (user_pub_key == HI_NULL) {
        hi_log_error("malloc for user_pub_key falied\n");
        return CRYS_FATAL_ERROR;
    }
    error = memcpy_s(user_pub_key, sizeof(CRYS_RSAUserPubKey_t), Userpub_key, sizeof(CRYS_RSAUserPubKey_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto End;
    }

    error = __CRYS_RSA_Get_ModSizeFromPubKey(user_pub_key, modulus_size_ptr);
    if (error != CRYS_OK) {
        hi_log_print_func_err(__CRYS_RSA_Get_ModSizeFromPubKey, error);
        goto End;
    }
End:
    if (user_pub_key != HI_NULL) {
        crypto_free(user_pub_key);
        user_pub_key = HI_NULL;
    }

    return error;
}

