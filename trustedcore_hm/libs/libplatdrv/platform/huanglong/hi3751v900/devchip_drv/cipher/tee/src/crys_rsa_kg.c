/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: rsa_kg
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "drv_osal_lib.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_rsa_error.h"
#include "crys_rsa_types.h"
#include "crys_rsa_local.h"
#include "crys_rsa_schemes.h"
#include "crys_rsa_kg.h"
#include "crys_rnd.h"
#include "crys_cipher_common.h"
#include "drv_cipher_kapi.h"

#define NUM_2                   2
#define SHIFT_8                 8
#define CRYS_RSA_SIZE_4         4
#define CRYS_RSA_SIZE_IN_BIT_17 17

CEXPORT_C CRYSError_t __CRYS_RSA_KG_GenerateKeyPair(DxUint8_t *PubExp_ptr,
                                                    DxUint16_t PubExpSizeInBytes,
                                                    DxUint32_t KeySize,
                                                    CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                    CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                    CRYS_RSAKGData_t *KeyGenData_ptr)
{
    hi_s32 ret;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    CRYSRSAPrivKey_t *private_key = HI_NULL;
    hi_u8 *key = HI_NULL;
    cryp_rsa_key rsa_key;
    hi_u32 i;

    /* ...... checking the key database handle pointer .................... */
    if (PubExp_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;
    }

    /* ...... checking the validity of the exponent pointer ............... */
    if (UserPrivKey_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the modulus pointer .............. */
    if (UserPubKey_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == DX_NULL) {
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;
    }

    /* ...... checking the exponent size .................. */
    if (PubExpSizeInBytes > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    /* set the public and private key structure pointers */
    pub_key = (CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
    private_key = (CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* ------------------------------------------------------------------------- */
    ret = memset_s(pub_key, sizeof(CRYSRSAPubKey_t), 0, sizeof(CRYSRSAPubKey_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = memset_s(private_key, sizeof(CRYSRSAPrivKey_t), 0, sizeof(CRYSRSAPrivKey_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = memset_s(KeyGenData_ptr, sizeof(CRYS_RSAKGData_t), 0, sizeof(CRYS_RSAKGData_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* ................ loading the public exponent to the structure .......... */
    if (PubExpSizeInBytes > CRYS_RSA_SIZE_4) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }
    pub_key->e[0] = 0;
    for (i = 0; i < PubExpSizeInBytes; i++) {
        pub_key->e[0] <<= SHIFT_8;
        pub_key->e[0] |= PubExp_ptr[i];
    }
    pub_key->eSizeInBits = crys_get_bit_num(PubExp_ptr, PubExpSizeInBytes);
    private_key->PriveKeyDb.NonCrt.e[0] = pub_key->e[0];
    private_key->PriveKeyDb.NonCrt.eSizeInBits = pub_key->eSizeInBits;

    /* if the size in bits is 0 - return error */
    if (pub_key->eSizeInBits == 0 || pub_key->eSizeInBits > CRYS_RSA_SIZE_IN_BIT_17) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_1 &&
        pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        return CRYS_RSA_INVALID_EXPONENT_VAL;
    }

    /* this initialization is required for the low level function (LLF) - indicates the required
    size of the key to be found */
    pub_key->nSizeInBits = KeySize;
    private_key->nSizeInBits = KeySize;
    key = (hi_u8 *)KeyGenData_ptr;

    rsa_key.n = key;
    rsa_key.d = rsa_key.n + RSA_MAX_RSA_KEY_LEN;
    rsa_key.p = rsa_key.d + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.q = rsa_key.p + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.dp = rsa_key.q + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.dq = rsa_key.dp + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.qp = rsa_key.dq + RSA_MAX_RSA_KEY_LEN / NUM_2;
    ret = kapi_rsa_gen_key(KeySize, pub_key->e[0], &rsa_key);
    if (ret != HI_SUCCESS) {
        hi_log_error("DRV_CIPHER_GenRsaKey_SW, err = 0x%x\n", ret);
        return CRYS_FATAL_ERROR;
    }

    ret = crys_bin2bn(pub_key->n, rsa_key.n, rsa_key.klen);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = crys_bin2bn(private_key->n, rsa_key.n, rsa_key.klen);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = crys_bin2bn(private_key->PriveKeyDb.NonCrt.d, rsa_key.d, rsa_key.klen);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.NonCrt.dSizeInBits = crys_get_bit_num(rsa_key.d, rsa_key.klen);

    /* set the mode to non CRT */
    private_key->OperationMode = CRYS_RSA_NoCrt;

    /* set the key source as internal */
    private_key->KeySource = CRYS_RSA_InternalKey;
    UserPrivKey_ptr->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    UserPubKey_ptr->valid_tag = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

    ret = memset_s(KeyGenData_ptr, sizeof(CRYS_RSAKGData_t), 0, sizeof(CRYS_RSAKGData_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    return CRYS_OK;
} /* END OF CRYS_RSA_KG_GenerateKeyPair */

CEXPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPair(DxUint8_t *PubExp_ptr,
                                                  DxUint16_t PubExpSizeInBytes,
                                                  DxUint32_t KeySize,
                                                  CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                  CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                  CRYS_RSAKGData_t *KeyGenData_ptr)
{
    DxUint8_t *pub_exp = HI_NULL;
    CRYS_RSAKGData_t *key_gen_data = HI_NULL;
    CRYSError_t error;

    if ((PubExp_ptr == HI_NULL)
        || (UserPrivKey_ptr == HI_NULL)
        || (UserPubKey_ptr == HI_NULL)
        || (KeyGenData_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pub_exp = (DxUint8_t *)crypto_malloc(PubExpSizeInBytes);
    if (pub_exp == HI_NULL) {
        hi_log_error("malloc for pub_exp falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memcpy_s(pub_exp, PubExpSizeInBytes, PubExp_ptr, PubExpSizeInBytes);
    if (error != HI_SUCCESS) {
        goto err;
    }

    key_gen_data = (CRYS_RSAKGData_t *)crypto_malloc(sizeof(CRYS_RSAKGData_t));
    if (key_gen_data == HI_NULL) {
        hi_log_error("malloc for key_gen_data falied\n");
        goto err;
    }
    error = memcpy_s(key_gen_data, sizeof(CRYS_RSAKGData_t), KeyGenData_ptr, sizeof(CRYS_RSAKGData_t));
    if (error != HI_SUCCESS) {
        goto err;
    }

    error = __CRYS_RSA_KG_GenerateKeyPair(pub_exp, PubExpSizeInBytes, KeySize,
                                          UserPrivKey_ptr, UserPubKey_ptr, key_gen_data);
err:
    if (pub_exp != HI_NULL) {
        crypto_free(pub_exp);
        pub_exp = HI_NULL;
    }
    if (key_gen_data != HI_NULL) {
        crypto_free(key_gen_data);
        key_gen_data = HI_NULL;
    }

    return error;
}

CEXPORT_C CRYSError_t __CRYS_RSA_KG_GenerateKeyPairCRT(DxUint8_t *PubExp_ptr,
                                                       DxUint16_t PubExpSizeInBytes,
                                                       DxUint32_t KeySize,
                                                       CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                       CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                       CRYS_RSAKGData_t *KeyGenData_ptr)
{
    hi_s32 ret;
    CRYSRSAPubKey_t *pub_key = HI_NULL;
    CRYSRSAPrivKey_t *private_key = HI_NULL;
    cryp_rsa_key rsa_key;
    hi_u8 *key = HI_NULL;
    hi_u32 i;

    /* ...... checking the key database handle pointer .................. */
    if (PubExp_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;
    }

    /* ...... checking the validity of the exponent pointer ............. */
    if (UserPrivKey_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the modulus pointer .............. */
    if (UserPubKey_ptr == DX_NULL) {
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;
    }

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == DX_NULL) {
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;
    }

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    /* set the public and private key structure pointers */
    pub_key = (CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
    private_key = (CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    ret = memset_s(UserPrivKey_ptr, sizeof(CRYS_RSAUserPrivKey_t), 0, sizeof(CRYS_RSAUserPrivKey_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = memset_s(UserPubKey_ptr, sizeof(CRYS_RSAUserPubKey_t), 0, sizeof(CRYS_RSAUserPubKey_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = memset_s(KeyGenData_ptr, sizeof(CRYS_RSAKGData_t), 0, sizeof(CRYS_RSAKGData_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (PubExpSizeInBytes > CRYS_RSA_SIZE_4) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }
    pub_key->e[0] = 0;
    for (i = 0; i < PubExpSizeInBytes; i++) {
        pub_key->e[0] <<= SHIFT_8;
        pub_key->e[0] |= PubExp_ptr[i];
    }
    pub_key->eSizeInBits = crys_get_bit_num(PubExp_ptr, PubExpSizeInBytes);

    /* if the size in bits is 0 - return error */
    if (pub_key->eSizeInBits == 0 || pub_key->eSizeInBits > CRYS_RSA_SIZE_IN_BIT_17) {
        return CRYS_RSA_INVALID_EXPONENT_SIZE;
    }

    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_1 &&
        pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pub_key->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        return CRYS_RSA_INVALID_EXPONENT_VAL;
    }

    /* this initialization is required for the low level function (LLF) - indicates the required
    size of the key to be found */
    pub_key->nSizeInBits = KeySize;
    private_key->nSizeInBits = KeySize;
    key = (hi_u8 *)KeyGenData_ptr;

    rsa_key.n = key;
    rsa_key.d = rsa_key.n + RSA_MAX_RSA_KEY_LEN;
    rsa_key.p = rsa_key.d + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.q = rsa_key.p + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.dp = rsa_key.q + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.dq = rsa_key.dp + RSA_MAX_RSA_KEY_LEN / NUM_2;
    rsa_key.qp = rsa_key.dq + RSA_MAX_RSA_KEY_LEN / NUM_2;
    ret = kapi_rsa_gen_key(KeySize, pub_key->e[0], &rsa_key);
    if (ret != HI_SUCCESS) {
        hi_log_error("DRV_CIPHER_GenRsaKey_SW, err = 0x%x\n", ret);
        return CRYS_FATAL_ERROR;
    }

    ret = crys_bin2bn(pub_key->n, rsa_key.n, rsa_key.klen);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = crys_bin2bn(private_key->n, rsa_key.n, rsa_key.klen);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    ret = crys_bin2bn(private_key->PriveKeyDb.Crt.P, rsa_key.p, rsa_key.klen >> 1);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.Crt.PSizeInBits = crys_get_bit_num(rsa_key.p, rsa_key.klen >> 1);
    ret = crys_bin2bn(private_key->PriveKeyDb.Crt.Q, rsa_key.q, rsa_key.klen >> 1);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.Crt.QSizeInBits = crys_get_bit_num(rsa_key.q, rsa_key.klen >> 1);
    ret = crys_bin2bn(private_key->PriveKeyDb.Crt.dP, rsa_key.dq, rsa_key.klen >> 1);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.Crt.dPSizeInBits = crys_get_bit_num(rsa_key.dp, rsa_key.klen >> 1);
    ret = crys_bin2bn(private_key->PriveKeyDb.Crt.dQ, rsa_key.dq, rsa_key.klen >> 1);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.Crt.dQSizeInBits = crys_get_bit_num(rsa_key.dq, rsa_key.klen >> 1);
    ret = crys_bin2bn(private_key->PriveKeyDb.Crt.qInv, rsa_key.qp, rsa_key.klen >> 1);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    private_key->PriveKeyDb.Crt.qInvSizeInBits = crys_get_bit_num(rsa_key.qp, rsa_key.klen >> 1);

    /* set the mode to CRT */
    private_key->OperationMode = CRYS_RSA_Crt;

    /* set the key source as internal */
    private_key->KeySource = CRYS_RSA_InternalKey;

    UserPrivKey_ptr->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    UserPubKey_ptr->valid_tag = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

    /* clear the KG data structure */
    ret = memset_s(KeyGenData_ptr, sizeof(CRYS_RSAKGData_t), 0, sizeof(CRYS_RSAKGData_t));
    if (ret != HI_SUCCESS) {
        return ret;
    }

    return CRYS_OK;
} /* END OF CRYS_RSA_KG_GenerateKeyPairCRT */

CEXPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPairCRT(DxUint8_t *PubExp_ptr,
                                                     DxUint16_t PubExpSizeInBytes,
                                                     DxUint32_t KeySize,
                                                     CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                     CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                     CRYS_RSAKGData_t *KeyGenData_ptr)
{
    DxUint8_t *pub_exp = HI_NULL;
    CRYS_RSAKGData_t *key_gen_data = HI_NULL;
    CRYSError_t error;

    if ((PubExp_ptr == HI_NULL)
        || (UserPrivKey_ptr == HI_NULL)
        || (UserPubKey_ptr == HI_NULL)
        || (KeyGenData_ptr == HI_NULL)) {
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pub_exp = (DxUint8_t *)crypto_malloc(PubExpSizeInBytes);
    if (pub_exp == HI_NULL) {
        hi_log_error("malloc for pub_exp falied\n");
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    error = memcpy_s(pub_exp, PubExpSizeInBytes, PubExp_ptr, PubExpSizeInBytes);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    key_gen_data = (CRYS_RSAKGData_t *)crypto_malloc(sizeof(CRYS_RSAKGData_t));
    if (key_gen_data == HI_NULL) {
        hi_log_error("malloc for key_gen_data falied\n");
        goto err;
    }
    error = memcpy_s(key_gen_data, sizeof(CRYS_RSAKGData_t), KeyGenData_ptr, sizeof(CRYS_RSAKGData_t));
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, error);
        goto err;
    }

    error = __CRYS_RSA_KG_GenerateKeyPairCRT(pub_exp, PubExpSizeInBytes, KeySize,
                                             UserPrivKey_ptr, UserPubKey_ptr, key_gen_data);
    if (error != HI_SUCCESS) {
        hi_log_print_func_err(__CRYS_RSA_KG_GenerateKeyPairCRT, error);
        goto err;
    }

err:
    if (pub_exp != HI_NULL) {
        crypto_free(pub_exp);
        pub_exp = HI_NULL;
    }
    if (key_gen_data != HI_NULL) {
        crypto_free(key_gen_data);
        key_gen_data = HI_NULL;
    }

    return error;
}
