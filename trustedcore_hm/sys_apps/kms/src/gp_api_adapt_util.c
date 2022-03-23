/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "gp_api_adapt_util.h"
#include "openssl/rsa.h"
#include "securec.h"
#include "tee_log.h"
#include "crypto_ext_api.h"
#include "crypto_wrapper.h"
#include "crypto_driver_adaptor.h"
#include "crypto_inner_defines.h"
#include "kms_pub_def.h"
#include "kms_tag_api.h"
#include "kms_asn1_api.h"
#include "gp_keyblob_operation.h"
#include "invoke.h"

uint32_t key_type_kms_to_gp(uint32_t kms_key_type)
{
    struct uint_to_uint key_type[] = {
        { KMS_KEY_TYPE_RSA, TEE_TYPE_RSA_KEYPAIR },
        { KMS_KEY_TYPE_RSA_PUBLIC, TEE_TYPE_RSA_PUBLIC_KEY },
        { KMS_KEY_TYPE_AES, TEE_TYPE_AES },
        { KMS_KEY_TYPE_HMAC, TEE_TYPE_HMAC_SHA256 },
        { KMS_KEY_TYPE_SIP_HASH, TEE_TYPE_SIP_HASH },
        { KMS_KEY_TYPE_ED25519, TEE_TYPE_ED25519_KEYPAIR },
        { KMS_KEY_TYPE_ED25519_PUBLIC, TEE_TYPE_ED25519_PUBLIC_KEY },
        { KMS_KEY_TYPE_ECDSA, TEE_TYPE_ECDSA_KEYPAIR },
        { KMS_KEY_TYPE_ECDSA_PUBLIC, TEE_TYPE_ECDSA_PUBLIC_KEY },
        { KMS_KEY_TYPE_SM2, TEE_TYPE_SM2_DSA_KEYPAIR },
        { KMS_KEY_TYPE_SM4, TEE_TYPE_SM4 },
        { KMS_KEY_TYPE_GENERIC, TEE_TYPE_GENERIC_SECRET },
    };
    uint32_t index = 0;
    while (index < array_size(key_type)) {
        if (kms_key_type == key_type[index].src)
            return key_type[index].dest;
        index++;
    }
    return INVALID_VALUE;
}


bool is_gcm_mode(uint32_t alg_type)
{
    bool is_gcm_mode = (alg_type == TEE_ALG_AES_GCM || alg_type == TEE_ALG_SM4_GCM);
    return is_gcm_mode;
}

static void insecure_block_padding_mode_check(uint32_t kms_alg_type, uint32_t hash_type, uint32_t pad_mode)
{
    if (kms_alg_type == KMS_ALG_AES_ECB || kms_alg_type == KMS_ALG_SM4_ECB)
        tlogw("Warning: insecure block mode ECB, kms alg type %u\n", kms_alg_type);
    else if (kms_alg_type == KMS_ALG_MD5 || kms_alg_type == KMS_ALG_SHA1)
        tlogw("Warning: insecure ALG %s, kms alg type %u\n",
            (kms_alg_type == KMS_ALG_MD5) ? "MD5" : "SHA1", kms_alg_type);
    else if (kms_alg_type == KMS_ALG_RSA && pad_mode == KMS_PAD_RSA_PKCS1_SIGN)
        tlogw("Warning: insecure padding mode PCKS1_V1_5, kms alg type %u\n", kms_alg_type);
    if (hash_type == KMS_HASH_MD5 || hash_type == KMS_HASH_SHA1)
        tlogw("warning: insecure hash mode %s, kms hash type %u\n",
            (hash_type == KMS_HASH_MD5) ? "MD5" : "SHA1",  hash_type);
}
uint32_t alg_type_kms_to_gp(uint32_t kms_alg_type, uint32_t hash_type, uint32_t pad_mod)
{
    insecure_block_padding_mode_check(kms_alg_type, hash_type, pad_mod);
    const struct uint_to_uint alg_type[] = {
        INDEX_KMS_25519,
        INDEX_KMS_RSA,
        INDEX_KMS_ECDSA,
        INDEX_KMS_MAC,
        INDEX_KMS_AES,
        INDEX_KMS_ALG_HASH,
        INDEX_KMS_HASH_TYPE,
        INDEX_KMS_SM
    };
    uint32_t index = 0;
    uint32_t kms_index = alg_hash_pad_index(kms_alg_type, hash_type, pad_mod);
    while (index < array_size(alg_type)) {
        if (kms_index == alg_type[index].src)
            return alg_type[index].dest;
        index++;
    }
    /* kms_alg_type, hash_type, pad_mode maybe a zero value for concat, not the real value, we don't print info */
    return INVALID_VALUE;
}

uint32_t mod_kms_to_gp(uint32_t kms_mod)
{
    const struct uint_to_uint mod_type[] = {
        { KMS_MODE_ENCRYPT, TEE_MODE_ENCRYPT },
        { KMS_MODE_DECRYPT, TEE_MODE_DECRYPT },
        { KMS_MODE_SIGN, TEE_MODE_SIGN },
        { KMS_MODE_VERIFY, TEE_MODE_VERIFY },
        { KMS_MODE_MAC, TEE_MODE_MAC },
        { KMS_MODE_DIGEST, TEE_MODE_DIGEST },
        { KMS_MODE_DERIVE, TEE_MODE_DERIVE },
    };
    uint32_t index = 0;
    while (index < array_size(mod_type)) {
        if (kms_mod == mod_type[index].src)
            return mod_type[index].dest;
        index++;
    }
    return INVALID_VALUE;
}

uint32_t get_ecc_cur(uint32_t key_type, uint32_t key_size)
{
    if (key_type == TEE_ECC_CURVE_SM2)
        return TEE_ECC_CURVE_SM2;
    const struct uint_to_uint ecc_cur[] = {
        { 192, TEE_ECC_CURVE_NIST_P192 },
        { 224, TEE_ECC_CURVE_NIST_P224 },
        { 256, TEE_ECC_CURVE_NIST_P256 },
        { 384, TEE_ECC_CURVE_NIST_P384 },
        { 521, TEE_ECC_CURVE_NIST_P521 },
    };
    uint32_t index = 0;
    while (index < array_size(ecc_cur)) {
        if (key_size == ecc_cur[index].src)
            return ecc_cur[index].dest;
        index++;
    }
    return INVALID_VALUE;
}

static TEE_Result init_koi_alg_type(struct gp_key_opera_input *koi, const struct kms_buffer_data *param_set)
{
    uint32_t alg_type = 0;
    uint32_t hash_type = 0;
    TEE_Result ret = get_key_param(&alg_type, KMS_TAG_OPERATION_ALGORITHM, param_set);
    if (ret != 0) {
        tloge("key opera input init: get algorithm type faield\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_key_param(&hash_type, KMS_TAG_HASH_TYPE, param_set);
    if (ret != 0)
        tlogd("key opera input init: get hash type faield\n");

    koi->hash_type = hash_type;
    uint32_t pad = 0;
    ret = get_key_param(&pad, KMS_TAG_PADDING, param_set);
    if (ret == 0)
        tlogd("key opera input init: pad in 0x%x\n", pad);

    koi->alg_type = alg_type_kms_to_gp(alg_type, hash_type, pad);
    if (koi->alg_type == INVALID_VALUE) {
        tloge("key opera input init:unspport alg 0x%x, hash_type 0x%x, padding mode %x\n", alg_type, hash_type, pad);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (alg_type == KMS_ALG_AES_GCM_V2 || alg_type == KMS_ALG_SM4_GCM)
        koi->alg_version = GCM_V2;
    if (alg_type == KMS_ALG_AES_GCM)
        koi->alg_version = GCM_V1;
    return TEE_SUCCESS;
}

static TEE_Result init_key_opera_crypto(const struct kms_buffer_data *param_set, struct gp_key_opera_input *koi)
{
    TEE_Result ret = get_key_param(&koi->iv, KMS_TAG_IV, param_set);
    if (ret != 0)
        tlogd("init_key_opera_crypto: get kms tag iv failed\n");

    ret = TEE_SUCCESS;
    if (is_gcm_mode(koi->alg_type)) {
        ret = get_key_param(&koi->aes_gcm_aad_data, KMS_TAG_GCM_AAD, param_set);
        if (ret != 0)
            tlogd("init_key_opera_crypto: get aad data failed\n");

        ret = get_key_param(&koi->gcm_tag_len, KMS_TAG_GCM_MAC_LEN, param_set);
        if (ret == 0) {
            if (koi->gcm_tag_len > GCM_TAG_MAX_LEN || koi->gcm_tag_len < GCM_TAG_MIN_LEN) {
                tloge("init key opera crypto:invalid gcm tag len %u\n", koi->gcm_tag_len);
                ret = TEE_ERROR_BAD_PARAMETERS;
            }
        } else {
            tloge("init key opera crypto: gcm need gcm mac len tag\n");
            ret = TEE_ERROR_BAD_PARAMETERS;
        }
    }
    return ret;
}

static void confirm_generic_key_type(uint32_t alg_type, uint32_t *key_type)
{
    switch (alg_type) {
        case TEE_ALG_AES_ECB_PKCS5:
        case TEE_ALG_AES_ECB_NOPAD:
        case TEE_ALG_AES_CBC_PKCS5:
        case TEE_ALG_AES_CBC_NOPAD:
        case TEE_ALG_AES_GCM:
        case TEE_ALG_AES_CMAC:
            *key_type = TEE_TYPE_AES;
            break;
        case TEE_ALG_HMAC_SHA256:
            *key_type = TEE_TYPE_HMAC_SHA256;
            break;
        default:
            tloge("generic key unspport alg type\n");
    }
}
TEE_Result init_key_opera_input(struct gp_key_opera_input *koi, const struct kms_buffer_data *key_blob,
    const struct kms_buffer_data *param_set, uint32_t kms_mod)
{
    bool check = (param_set == NULL || koi == NULL);
    if (check) {
        tloge("init key opera input: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    koi->mode = mod_kms_to_gp(kms_mod);
    if (koi->mode == INVALID_VALUE) {
        tloge("key opera input init: valid mode %u\n", kms_mod);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = init_koi_alg_type(koi, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("key opera input init: init alg type fail\n");
        return ret;
    }
    if ((koi->mode == TEE_MODE_ENCRYPT || koi->mode == TEE_MODE_DECRYPT)) {
        ret = init_key_opera_crypto(param_set, koi);
        if (ret != TEE_SUCCESS) {
            tloge("init key opera input gcm fail\n");
            return ret;
        }
    }

    if (key_blob != NULL && key_blob->buffer != NULL) {
        struct gp_key_base_info *kbi = (struct gp_key_base_info *)key_blob->buffer;
        if (kbi->key_type == TEE_TYPE_GENERIC_SECRET)
            confirm_generic_key_type(koi->alg_type, &(kbi->key_type));
        TEE_ObjectHandle key_obj = NULL;
        ret = gp_keyblob_to_key(key_blob, NULL, &key_obj);
        if (ret != TEE_SUCCESS) {
            tloge("gp crypto key is invalid\n");
            return TEE_ERROR_BAD_FORMAT;
        }
        koi->key_obj = key_obj;
        koi->key_size = kbi->key_size;
    }
    return TEE_SUCCESS;
}

static bool check_kms_buffer(const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    if (in_data == NULL || in_data->buffer == NULL || in_data->length == 0 ||
        out_data == NULL || out_data->buffer == NULL || out_data->length == 0)
        return false;

    return true;
}

TEE_Result digest(uint32_t alg_type, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    TEE_Result ret;
    TEE_OperationHandle operation = NULL;

    if (!check_kms_buffer(in_data, out_data)) {
        tloge("digest: buffer is null\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    ret = TEE_AllocateOperation(&operation, alg_type, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("digest:alloc operation fail");
        return ret;
    }

    TEE_DigestUpdate(operation, (void *)in_data->buffer, in_data->length);
    size_t digest_len = out_data->length;
    ret = TEE_DigestDoFinal(operation, NULL, 0, (void *)out_data->buffer, &digest_len);
    if (ret != TEE_SUCCESS) {
        tloge("digest:dofinal fail\n");
        goto error_free;
    }
    out_data->length = digest_len;
error_free:
    if (operation != NULL)
        TEE_FreeOperation(operation);
    return ret;
}

TEE_Result sm2_digest(uint32_t alg_type, struct gp_key_opera_input *koi, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_Result ret;
    TEE_OperationHandle operation = NULL;

    if (!check_kms_buffer(in_data, out_data)) {
        tloge("sm2 digest: buffer is null\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    ret = TEE_AllocateOperation(&operation, alg_type, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("sm2 digest:alloc operation fail\n");
        return ret;
    }
    koi->crypto_oper = operation;
    ret = sm2_begin(koi);
    if (ret != TEE_SUCCESS) {
        tloge("sm2 begin in digest failed\n");
        goto error_free;
    }
    size_t digest_len = out_data->length;
    ret = TEE_DigestDoFinal(koi->crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &digest_len);
    if (ret != TEE_SUCCESS) {
        tloge("sm2 digest:dofinal fail\n");
        goto error_free;
    }
    out_data->length = digest_len;
error_free:
    if (koi->crypto_oper != NULL) {
        TEE_FreeOperation(koi->crypto_oper);
        koi->crypto_oper = NULL;
    }
    return ret;
}

TEE_Result digest_for_sign_data(struct gp_key_opera_input *koi, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_Result ret;
    uint32_t alg = alg_type_kms_to_gp(0, koi->hash_type, 0);
    if (alg == INVALID_VALUE) {
        tloge("digest for sign data: not support hash type %u\n", koi->hash_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (koi->alg_type == TEE_ALG_SM2_DSA_SM3) {
        ret = sm2_digest(alg, koi, in_data, out_data);
    } else {
        ret = digest(alg, in_data, out_data);
    }

    if (ret != TEE_SUCCESS) {
        tloge("digest for sign data: digest fail\n");
        return ret;
    }
    return ret;
}

static TEE_Result sm2_za_add_fix_id(uint8_t *out, uint32_t *out_len)
{
    /* Default user id */
    uint8_t id[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    uint32_t id_len = sizeof(id);
    /* ENTLA len is 2, filling in idLen's length, in bits */
    uint8_t id_bits[ENTLA_LEN] = {0};
    id_bits[0] = ((id_len * BYTE_TO_BIT) >> BYTE_TO_BIT) % BYTE_MAX;
    id_bits[1] = (id_len * BYTE_TO_BIT) % BYTE_MAX;

    errno_t rc = memcpy_s(out, *out_len, id_bits, ENTLA_LEN);
    if (rc != EOK) {
        tloge("add fix id: copy len fail\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    rc = memcpy_s(out + ENTLA_LEN, *out_len - ENTLA_LEN, id, id_len);
    if (rc != EOK) {
        tloge("add fix id: copy id fail %u\n", *out_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    *out_len = ENTLA_LEN + id_len;
    return TEE_SUCCESS;
}

static TEE_Result sm2_za_add_fix_curve(uint8_t *out, uint32_t *out_len)
{
    /* Curve parameter a */
    uint8_t a[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    };
    /* Curve parameter b */
    uint8_t b[] = {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    };
    errno_t rc = memcpy_s(out, *out_len, a, sizeof(a));
    if (rc != EOK) {
        tloge("add fix cure: copy a fail %u\n", *out_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    rc = memcpy_s(out + sizeof(a), *out_len - sizeof(a), b, sizeof(b));
    if (rc != EOK) {
        tloge("add fix cure: copy b fail %u\n", *out_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    *out_len = sizeof(a) + sizeof(b);
    return TEE_SUCCESS;
}

static TEE_Result sm2_za_add_base_point(uint8_t *out, uint32_t *out_len)
{
    /* Curve parameter xg */
    uint8_t xg[] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    };
    /* Curve parameter yg */
    uint8_t yg[] = {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
    };

    errno_t rc = memcpy_s(out, *out_len, xg, sizeof(xg));
    if (rc != EOK) {
        tloge("add fix cure: copy xg fail %u\n", *out_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    rc = memcpy_s(out + sizeof(xg), *out_len - sizeof(xg), yg, sizeof(yg));
    if (rc != EOK) {
        tloge("add fix cure: copy yg fail %u\n", *out_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    *out_len = sizeof(xg) + sizeof(yg);
    return TEE_SUCCESS;
}

static TEE_Result sm2_za_add_public_key(TEE_ObjectHandle key_obj, uint8_t *out, uint32_t *out_len)
{
    if (key_obj == NULL) {
        tloge("sm2 za add pub key: key is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    size_t x_len = *out_len;
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_X, out, &x_len);
    if (ret != TEE_SUCCESS || *out_len <= x_len) {
        tloge("sm2 za add pub key: get public x fail\n");
        return ret;
    }

    size_t y_len = *out_len - x_len;
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_Y, out + x_len, &y_len);
    if (ret != TEE_SUCCESS) {
        tloge("sm2 za add pub key: get public y fail\n");
        return ret;
    }
    *out_len = x_len + y_len;
    return ret;
}

TEE_Result get_sm2_za(TEE_ObjectHandle key_obj, struct kms_buffer_data *digest_data)
{
    TEE_Result ret;
    uint8_t za_data[SM2_ZA_DATA_MAX_LEN] = {0};
    uint32_t za_data_len;
    uint32_t za_left_len = SM2_ZA_DATA_MAX_LEN;

    ret = sm2_za_add_fix_id(za_data, &za_left_len);
    if (ret != TEE_SUCCESS) {
        tloge("get sm2 za: get fix id failed\n");
        return ret;
    }
    za_data_len = za_left_len;
    za_left_len = SM2_ZA_DATA_MAX_LEN - za_data_len;

    ret = sm2_za_add_fix_curve(za_data + za_data_len, &za_left_len);
    if (ret != TEE_SUCCESS) {
        tloge("get sm2 za: sm2 add fix curve failed\n");
        return ret;
    }
    za_data_len += za_left_len;
    za_left_len = SM2_ZA_DATA_MAX_LEN - za_data_len;

    ret = sm2_za_add_base_point(za_data + za_data_len, &za_left_len);
    if (ret != TEE_SUCCESS) {
        tloge("get sm2 za: sm2 add base point failed\n");
        return ret;
    }
    za_data_len += za_left_len;
    za_left_len = SM2_ZA_DATA_MAX_LEN - za_data_len;

    ret = sm2_za_add_public_key(key_obj, za_data + za_data_len, &za_left_len);
    if (ret != TEE_SUCCESS) {
        tloge("get sm2 za: sm2 add public key failed\n");
        return ret;
    }
    za_data_len += za_left_len;
    struct kms_buffer_data in_data;
    in_data.buffer = za_data;
    in_data.length = za_data_len;
    ret = digest(TEE_ALG_SM3, &in_data, digest_data);
    if (ret != TEE_SUCCESS)
        tloge("sm2 hash dofinal failed\n");

    return ret;
}

TEE_Result sm2_alloc_add_za_data(uint32_t alg_type, TEE_ObjectHandle key_obj, struct kms_buffer_data *in_data)
{
    if (alg_type != TEE_ALG_SM2_DSA_SM3)
        return TEE_SUCCESS;

    if (in_data == NULL) {
        tloge("alloc add za: in buffer is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t za_dig[SM2_ZA_DATA_MAX_LEN] = {0};
    struct kms_buffer_data digest_data;
    digest_data.length = SM2_ZA_DATA_MAX_LEN;
    digest_data.buffer = za_dig;
    TEE_Result ret = get_sm2_za(key_obj, &digest_data);
    if (ret != TEE_SUCCESS) {
        tloge("alloc add za: get sm2 za fail\n");
        return ret;
    }

    // in_data->length not bigger than MAX_IN_BUFFER_LEN, digest_data->length not bigger than SM2_ZA_DATA_MAX_LEN
    uint32_t out_len = in_data->length + digest_data.length;
    if (out_len > (MAX_IN_BUFFER_LEN + SM2_ZA_DATA_MAX_LEN)) {
        tloge("malloc out_len is larger than max len!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *out_buffer = (uint8_t *)TEE_Malloc(out_len, 0);
    if (out_buffer == NULL) {
        tloge("alloc add za: alloc %u fail\n", out_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memcpy_s(out_buffer, out_len, digest_data.buffer, digest_data.length);
    if (rc != EOK) {
        tloge("alloc add za: memcpy digest fail\n");
        TEE_Free(out_buffer);
        return TEE_ERROR_GENERIC;
    }
    if (in_data->buffer != NULL && in_data->length != 0) {
        rc = memcpy_s(out_buffer + digest_data.length, in_data->length, in_data->buffer, in_data->length);
        if (rc != EOK) {
            tloge("alloc add za: memcpy indata fail\n");
            TEE_Free(out_buffer);
            return TEE_ERROR_GENERIC;
        }
    }
    // in_data old buffer is in param, not need free
    in_data->buffer = out_buffer;
    in_data->length = out_len;
    return TEE_SUCCESS;
}

void sm2_free_alloc_in_data(uint32_t alg_type, struct kms_buffer_data *in_data)
{
    if (alg_type != TEE_ALG_SM2_DSA_SM3)
        return;

    if (in_data == NULL) {
        tloge("alloc free za: in buffer is null\n");
        return;
    }
    TEE_Free(in_data->buffer);
    in_data->buffer = NULL;
    in_data->length = 0;
}

TEE_Result sm2_begin(struct gp_key_opera_input *koi)
{
    uint8_t za_dig[SM2_ZA_DATA_MAX_LEN] = {0};
    struct kms_buffer_data digest_data;
    digest_data.length = SM2_ZA_DATA_MAX_LEN;
    digest_data.buffer = za_dig;
    TEE_Result ret = get_sm2_za(koi->key_obj, &digest_data);
    if (ret != TEE_SUCCESS) {
        tloge("alloc add za: get sm2 za fail\n");
        return ret;
    }
    TEE_DigestUpdate(koi->crypto_oper, digest_data.buffer, digest_data.length);
    return TEE_SUCCESS;
}

TEE_Result import_symmetry_key(const struct kms_buffer_data *in_key, TEE_ObjectHandle keyobj)
{
    bool condition = (keyobj == NULL || in_key == NULL || in_key->buffer == NULL);
    if (condition) {
        tloge("import symmetry key: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, in_key->buffer, in_key->length);
    TEE_Result ret = TEE_PopulateTransientObject(keyobj, &attr, 1);
    if (ret != TEE_SUCCESS)
        tloge("set symmetry key: populate key failed: 0x%x\n", ret);
    return ret;
}

TEE_Result export_symmetry_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_key)
{
    bool condition = (keyobj == NULL || out_key == NULL || out_key->buffer == NULL);
    if (condition) {
        tloge("export symm key: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t key_len = out_key->length;
    TEE_Result ret = TEE_GetObjectBufferAttribute(keyobj, TEE_ATTR_SECRET_VALUE, (void *)out_key->buffer, &key_len);
    if (ret != TEE_SUCCESS) {
        tloge("export symm key: get secret value fail\n");
        return ret;
    }
    out_key->length = key_len;
    return ret;
}

TEE_Result export_rsa_public_key(TEE_ObjectHandle rsa_keyobj, struct kms_buffer_data *out_pub_key)
{
    TEE_Result ret;

    bool condition = (rsa_keyobj == NULL || out_pub_key == NULL || out_pub_key->buffer == NULL);
    if (condition) {
        tloge("get rsa pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (out_pub_key->length < sizeof(rsa_pub_key_t)) {
        tloge("get rsa pub: short public key buff len %u\n", out_pub_key->length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    rsa_pub_key_t *rsa_pub_key = (rsa_pub_key_t *)out_pub_key->buffer;
    size_t n_len = sizeof(rsa_pub_key->n);
    size_t e_len = sizeof(rsa_pub_key->e);

    ret = TEE_GetObjectBufferAttribute(rsa_keyobj, TEE_ATTR_RSA_MODULUS, (void *)rsa_pub_key->n, &n_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub: Get info of modulus failed: 0x%x\n", ret);
        return ret;
    }
    rsa_pub_key->n_len = n_len;

    ret = TEE_GetObjectBufferAttribute(rsa_keyobj, TEE_ATTR_RSA_PUBLIC_EXPONENT, (void *)rsa_pub_key->e, &e_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub: Get info of public failed: 0x%x\n", ret);
        return ret;
    }
    rsa_pub_key->e_len = e_len;

    out_pub_key->length = sizeof(*rsa_pub_key);
    return TEE_SUCCESS;
}

TEE_Result import_rsa_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle rsa_keyobj)
{
    TEE_Result ret;

    bool condition = (rsa_keyobj == NULL || in_pub_key == NULL || in_pub_key->buffer == NULL);
    if (condition) {
        tloge("import rsa pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (in_pub_key->length < sizeof(rsa_pub_key_t)) {
        tloge("import rsa pub: short public key len %u\n", in_pub_key->length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    rsa_pub_key_t *rsa_pub_key = (rsa_pub_key_t *)in_pub_key->buffer;

    if (rsa_pub_key->n_len > sizeof(rsa_pub_key->n) || rsa_pub_key->e_len > sizeof(rsa_pub_key->e)) {
        tloge("import rsa pub: bad key len n %u e %u\n", rsa_pub_key->n_len, rsa_pub_key->e_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Attribute attr[RSA_PUB_KEY_ATTR_LEN];
    TEE_InitRefAttribute(&attr[0], TEE_ATTR_RSA_MODULUS, rsa_pub_key->n, rsa_pub_key->n_len);
    TEE_InitRefAttribute(&attr[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_pub_key->e, rsa_pub_key->e_len);
    ret = TEE_PopulateTransientObject(rsa_keyobj, attr, RSA_PUB_KEY_ATTR_LEN);
    if (ret != TEE_SUCCESS)
        tloge("set rsa pub: populate rsa pub key failed: 0x%x\n", ret);

    return ret;
}

static TEE_Result convert_big_num_to_buffer(BIGNUM *big_num, uint8_t *out, uint32_t *out_len)
{
    bool check = ((big_num == NULL) || (out == NULL) || (out_len == NULL));
    if (check) {
        tloge("Invalid param in convert big num to buffer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t big_num_len = (uint32_t)BN_num_bytes(big_num);
    if (*out_len < big_num_len || *out_len > UINT32_MAX) {
        tloge("Out length %u, less than big num length %u, or too large\n", *out_len, big_num_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *rsa_buff = (uint8_t *)TEE_Malloc(big_num_len + 1, 0);
    if (rsa_buff == NULL) {
        tloge("Malloc memory for big num failed, size=%u\n", big_num_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    size_t write_len = (size_t)BN_bn2bin(big_num, rsa_buff);
    if (write_len != big_num_len) {
        tloge("Convert big num to buffer failed, bignum_len=%u, write_len=%zu\n", big_num_len, write_len);
        TEE_Free(rsa_buff);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s(out, *out_len, rsa_buff, big_num_len);
    TEE_Free(rsa_buff);
    rsa_buff = NULL;
    if (rc != EOK) {
        tloge("Copy rsa buff to param failed\n");
        return TEE_ERROR_GENERIC;
    }

    *out_len = big_num_len;
    return TEE_SUCCESS;
}

static void init_rsa_key(rsa_priv_key_t *priv_key)
{
    (void)memset_s(priv_key, sizeof(*priv_key), 0x0, sizeof(*priv_key));
    priv_key->e_len = sizeof(priv_key->e);
    priv_key->n_len = sizeof(priv_key->n);
    priv_key->d_len = sizeof(priv_key->d);
    priv_key->p_len = sizeof(priv_key->p);
    priv_key->q_len = sizeof(priv_key->q);
    priv_key->dp_len = sizeof(priv_key->dp);
    priv_key->dq_len = sizeof(priv_key->dq);
    priv_key->qinv_len = sizeof(priv_key->qinv);
}

static TEE_Result populate_gp_key(BIGNUM **bg_num_key, uint32_t attr_count, TEE_ObjectHandle rsa_keyobj)
{
    rsa_priv_key_t priv_key;
    init_rsa_key(&priv_key);
    uint8_t *key_element[RSA_KEY_PAIR_ATTRIBUTE_COUNT] = { priv_key.n, priv_key.e, priv_key.d, priv_key.p,
        priv_key.q, priv_key.dp, priv_key.dq, priv_key.qinv };
    uint32_t *key_ele_len[RSA_KEY_PAIR_ATTRIBUTE_COUNT] = { &priv_key.n_len, &priv_key.e_len, &priv_key.d_len,
        &priv_key.p_len, &priv_key.q_len, &priv_key.dp_len, &priv_key.dq_len, &priv_key.qinv_len };
    uint32_t attr_id[RSA_KEY_PAIR_ATTRIBUTE_COUNT] = { TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT,
        TEE_ATTR_RSA_PRIVATE_EXPONENT, TEE_ATTR_RSA_PRIME1, TEE_ATTR_RSA_PRIME2, TEE_ATTR_RSA_EXPONENT1,
        TEE_ATTR_RSA_EXPONENT2, TEE_ATTR_RSA_COEFFICIENT };
    TEE_Attribute attr[RSA_KEY_PAIR_ATTRIBUTE_COUNT];
    (void)memset_s(attr, sizeof(attr), 0x0, sizeof(attr));

    TEE_Result ret;
    uint32_t i;
    for (i = 0; i < attr_count; i++) {
        ret = convert_big_num_to_buffer(bg_num_key[i], key_element[i], key_ele_len[i]);
        if (ret != TEE_SUCCESS) {
            tloge("convert bignum[%u] to buf failed, ret=0x%x\n", i, ret);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        TEE_InitRefAttribute(&attr[i], attr_id[i], key_element[i], *key_ele_len[i]);
    }
    ret = TEE_PopulateTransientObject(rsa_keyobj, attr, attr_count);
    if (ret != TEE_SUCCESS)
        tloge("populate rsa key pair failed: 0x%x\n", ret);
    return ret;
}

static TEE_Result convert_rsa_boring_to_gp_key(RSA *rsa_key, TEE_ObjectHandle rsa_keyobj)
{
    struct rsa_key_pair_bignum key_pair_bignum = {0};
    RSA_get0_key(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_n),
        (const BIGNUM **)&(key_pair_bignum.bn_e), (const BIGNUM **)&(key_pair_bignum.bn_d));
    RSA_get0_factors(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_p), (const BIGNUM **)&(key_pair_bignum.bn_q));
    RSA_get0_crt_params(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_dp),
        (const BIGNUM **)&(key_pair_bignum.bn_dq), (const BIGNUM **)&(key_pair_bignum.bn_qinv));

    bool crt = (key_pair_bignum.bn_p != NULL && key_pair_bignum.bn_q != NULL && key_pair_bignum.bn_dp != NULL &&
        key_pair_bignum.bn_dq != NULL && key_pair_bignum.bn_qinv != NULL);
    BIGNUM *bn_array[RSA_KEY_PAIR_ATTRIBUTE_COUNT] = { key_pair_bignum.bn_n, key_pair_bignum.bn_e,
        key_pair_bignum.bn_d, key_pair_bignum.bn_p, key_pair_bignum.bn_q, key_pair_bignum.bn_dp,
        key_pair_bignum.bn_dq, key_pair_bignum.bn_qinv };
    uint32_t attr_count = (crt ? RSA_KEY_PAIR_ATTRIBUTE_COUNT : RSA_KEY_PAIR_ATTRIBUTE_COUNT_NO_CRT);

    rsa_keyobj->CRTMode = (crt ? GP_CRT_MODE : GP_NOCRT_MODE);
    TEE_Result ret = populate_gp_key(bn_array, attr_count, rsa_keyobj);
    if (ret != TEE_SUCCESS)
        tloge("populcate gp key by bignum array failed, ret = 0x%x\n", ret);

    return ret;
}

TEE_Result import_rsa_keypair_pkcs1(const struct kms_buffer_data *in_key, TEE_ObjectHandle rsa_keyobj)
{
    TEE_Result ret;

    bool condition = (rsa_keyobj == NULL || in_key == NULL || in_key->buffer == NULL);
    if (condition) {
        tloge("import rsa pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *key = in_key->buffer;
    RSA *rsa = d2i_RSAPrivateKey(NULL, (const uint8_t **)&key, in_key->length);
    if (rsa == NULL) {
        tloge("parse rsa keypair failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = convert_rsa_boring_to_gp_key(rsa, rsa_keyobj);
    if (ret != TEE_SUCCESS)
        tloge("convert pkcs1 key to gp key failed, ret=0x%x\n", ret);

    return ret;
}

TEE_Result export_ecdsa_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key)
{
    TEE_Result ret;

    bool condition = (keyobj == NULL || out_pub_key == NULL || out_pub_key->buffer == NULL);
    if (condition) {
        tloge("get ecdsa pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (out_pub_key->length < sizeof(ecc_pub_key_t)) {
        tloge("get ecdsa pub: short public key len %u\n", out_pub_key->length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_pub_key_t *ecc_pub_key = (ecc_pub_key_t *)out_pub_key->buffer;
    size_t x_len = sizeof(ecc_pub_key->x);
    size_t y_len = sizeof(ecc_pub_key->y);

    ret = TEE_GetObjectBufferAttribute(keyobj, TEE_ATTR_ECC_PUBLIC_VALUE_X, (void *)ecc_pub_key->x, &x_len);
    if (ret != TEE_SUCCESS) {
        tloge("get ecdsa pub: Get info of x failed: 0x%x\n", ret);
        return ret;
    }
    ecc_pub_key->x_len = x_len;

    ret = TEE_GetObjectBufferAttribute(keyobj, TEE_ATTR_ECC_PUBLIC_VALUE_Y, (void *)ecc_pub_key->y, &y_len);
    if (ret != TEE_SUCCESS) {
        tloge("get ecdsa pub: Get info of y failed: 0x%x\n", ret);
        return ret;
    }
    ecc_pub_key->y_len = y_len;

    TEE_Attribute attr;
    ret = TEE_GetObjectValueAttribute(keyobj, TEE_ATTR_ECC_CURVE, &attr.content.value.a, &attr.content.value.b);
    if (ret != TEE_SUCCESS) {
        tloge("get ecdsa pub: Get info of eurve failed: 0x%x\n", ret);
        return ret;
    }
    ecc_pub_key->domain = attr.content.value.a;

    out_pub_key->length = sizeof(*ecc_pub_key);
    return TEE_SUCCESS;
}

TEE_Result import_ecdsa_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle keyobj)
{
    TEE_Result ret;

    bool condition = (keyobj == NULL || in_pub_key == NULL || in_pub_key->buffer == NULL);
    if (condition) {
        tloge("import ecdsa pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (in_pub_key->length < sizeof(ecc_pub_key_t)) {
        tloge("import ecdsa pub: short public key len %u, %zu\n", in_pub_key->length, sizeof(ecc_pub_key_t));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_pub_key_t *ecc_pub_key = (ecc_pub_key_t *)in_pub_key->buffer;

    if (ecc_pub_key->x_len > sizeof(ecc_pub_key->x) || ecc_pub_key->y_len > sizeof(ecc_pub_key->y)) {
        tloge("import ecdsa pub: bad key len n %u e %u\n", ecc_pub_key->x_len, ecc_pub_key->y_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Attribute attr[ECDSA_PUB_KEY_ATTR_LEN];
    TEE_InitRefAttribute(&attr[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, ecc_pub_key->x, ecc_pub_key->x_len);
    TEE_InitRefAttribute(&attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecc_pub_key->y, ecc_pub_key->y_len);
    TEE_InitValueAttribute(&attr[2], TEE_ATTR_ECC_CURVE, ecc_pub_key->domain, 0);
    ret = TEE_PopulateTransientObject(keyobj, attr, ECDSA_PUB_KEY_ATTR_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("import ecdsa pub: populate ecdsa pub key failed: 0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result export_sm2_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key)
{
    bool condition = (keyobj == NULL || out_pub_key == NULL || out_pub_key->buffer == NULL);
    if (condition) {
        tloge("get sm2 pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ecc_pub_key_t ecc_pub_key;
    struct kms_buffer_data sm2_pub_key;
    sm2_pub_key.buffer = (uint8_t *)&ecc_pub_key;
    sm2_pub_key.length = sizeof(ecc_pub_key);
    TEE_Result ret = export_ecdsa_public_key(keyobj, &sm2_pub_key);
    if (ret != TEE_SUCCESS) {
        tloge("get sm2 pubkey faild\n");
        return ret;
    }
    ret = ecc_pubkey_to_asn1(&sm2_pub_key, out_pub_key);
    if (ret != TEE_SUCCESS)
        tloge("get sm2 pub: pubkey asn1 encode failed: 0x%x\n", ret);
    return ret;
}

TEE_Result export_ed25519_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key)
{
    TEE_Result ret;

    bool condition = (keyobj == NULL || out_pub_key == NULL || out_pub_key->buffer == NULL);
    if (condition) {
        tloge("get ed22519 pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t buffer_len = out_pub_key->length;
    ret = TEE_GetObjectBufferAttribute(keyobj, TEE_ATTR_ED25519_PUBLIC_VALUE, (void *)out_pub_key->buffer, &buffer_len);
    if (ret != TEE_SUCCESS) {
        tloge("get ed22519 pub: Get pub key failed: 0x%x\n", ret);
        return ret;
    }

    out_pub_key->length = buffer_len;
    return TEE_SUCCESS;
}

TEE_Result import_ed25519_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle keyobj)
{
    TEE_Result ret;

    bool condition = (keyobj == NULL || in_pub_key == NULL || in_pub_key->buffer == NULL);
    if (condition) {
        tloge("get ed25519 pub: Invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Attribute attr[ED25519_PUB_KEY_ATTR_LEN];
    TEE_InitRefAttribute(&attr[0], TEE_ATTR_ED25519_PUBLIC_VALUE, in_pub_key->buffer, in_pub_key->length);
    ret = TEE_PopulateTransientObject(keyobj, attr, ED25519_PUB_KEY_ATTR_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("set ed25519 pub: populate ed25519 pub key failed: 0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

bool check_is_rsa_alg(uint32_t alg)
{
    bool check = (alg == TEE_ALG_RSAES_PKCS1_V1_5 ||
                  alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 ||
                  alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 ||
                  alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 ||
                  alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 ||
                  alg == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512);
    return check;
}

TEE_Result crypto_rsa(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi, bool is_finish)
{
    /* AES GCM Mode doesn't need aad, so that AADLen = 0 */
    TEE_Result ret;

    bool condition = (koi == NULL || koi->in_data == NULL || koi->out_data == NULL);
    if (condition) {
        tloge("crypto rsa invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t dest_len = koi->out_data->length;
    uint8_t *in_buffer = koi->in_data->buffer;
    size_t in_len = koi->in_data->length;
    if (is_finish) {
        in_buffer = koi->cache_data.buffer;
        in_len = koi->cache_data.length;
    }
    if (koi->mode == TEE_MODE_ENCRYPT) {
        ret = TEE_AsymmetricEncrypt(crypto_oper, NULL, 0, in_buffer, in_len,
                                    koi->out_data->buffer, &dest_len);
    } else {
        ret = TEE_AsymmetricDecrypt(crypto_oper, NULL, 0, in_buffer, in_len,
                                    koi->out_data->buffer, &dest_len);
    }
    if (ret != TEE_SUCCESS)
        tloge("rsa crypto: %s fail in len %zu out len %u\n", koi->mode == TEE_MODE_ENCRYPT ? "encrypto" : "decrypto",
              in_len, koi->out_data->length);
    koi->out_data->length = dest_len;
    return ret;
}
