/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "gp_api_adaptation.h"
#include "kms_pub_def.h"
#include "kms_tag_api.h"
#include "securec.h"
#include "tee_log.h"
#include "crypto_ext_api.h"
#include "gp_keyblob_operation.h"
#include "gp_api_adapt_util.h"

static void insecure_alg_keysize_check(uint32_t key_type, uint32_t key_size)
{
    bool insecure = ((key_type == TEE_TYPE_ECDSA_KEYPAIR && key_size < ECDSA_MIN_SECURE_KEY_LEN) ||
        (key_type == TEE_TYPE_RSA_KEYPAIR && key_size < RSA_MIN_SECURE_KEY_LEN));
    if (insecure)
        tlogw("Warning: ALG %s, Key size %u is insecure!\n",
            ((key_type == TEE_TYPE_ECDSA_KEYPAIR) ? "ECDSA" : "RSA"), key_size);
}
static TEE_Result create_key(uint32_t key_type, uint32_t key_size, struct kms_buffer_data *key_blob)
{
    insecure_alg_keysize_check(key_type, key_size);
    TEE_ObjectHandle key_obj = NULL;
    TEE_Result ret = TEE_AllocateTransientObject(key_type, key_size, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("Allocate Transient Object fail; ret = 0x%x\n", ret);
        return ret;
    }
    if (key_type == TEE_TYPE_ECDSA_KEYPAIR || key_type == TEE_ECC_CURVE_SM2) {
        TEE_Attribute attr;
        uint32_t cur_type = get_ecc_cur(key_type, key_size);
        if (cur_type == INVALID_VALUE) {
            tloge("create key: error ecc keysize %u\n", key_size);
            TEE_FreeTransientObject(key_obj);
            key_obj = NULL;
            return TEE_ERROR_BAD_PARAMETERS;
        }
        TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, cur_type, 0);
        ret = TEE_GenerateKey(key_obj, key_size, &attr, 1);
    } else {
        ret = TEE_GenerateKey(key_obj, key_size, NULL, 0);
    }

    if (ret != TEE_SUCCESS) {
        tloge("create key: tee generate key fail, key type 0x%x, key size %u\n", key_type, key_size);
        TEE_FreeTransientObject(key_obj);
        key_obj = NULL;
        return ret;
    }
    struct gp_key_base_info bi = { 0 };
    bi.version = KMS_KEY_VERSION_2;
    bi.key_type = key_type;
    bi.key_size = key_size;
    ret = gp_key_to_buffer(key_obj, &bi, key_blob);
    TEE_FreeTransientObject(key_obj);
    key_obj = NULL;
    if (ret != TEE_SUCCESS)
        tloge("create key: key to buffer fail\n");
    return ret;
}

static TEE_Result import_key_format_raw(uint32_t key_type, const struct kms_buffer_data *in_key,
    TEE_ObjectHandle key_obj)
{
    TEE_Result ret;
    switch (key_type) {
    case TEE_TYPE_AES:
    case TEE_TYPE_SM4:
    case TEE_TYPE_SIP_HASH:
    case TEE_TYPE_GENERIC_SECRET:
    case TEE_TYPE_HMAC_SHA256:
        ret = import_symmetry_key(in_key, key_obj);
        break;
    case TEE_TYPE_RSA_PUBLIC_KEY:
        ret = import_rsa_public_key(in_key, key_obj);
        break;
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
        ret = import_ecdsa_public_key(in_key, key_obj);
        break;
    case TEE_TYPE_ED25519_PUBLIC_KEY:
        ret = import_ed25519_public_key(in_key, key_obj);
        break;
    default:
        tloge("import key format raw: unsupport key type 0x%x\n", key_type);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
    return ret;
}

static TEE_Result import_key_format_pkcs1(uint32_t key_type, const struct kms_buffer_data *in_key,
    TEE_ObjectHandle key_obj)
{
    TEE_Result ret;
    switch (key_type) {
    case TEE_TYPE_RSA_KEYPAIR:
        ret = import_rsa_keypair_pkcs1(in_key, key_obj);
        break;
    default:
        tloge("import key format pkcs#1: unsupport key type 0x%x\n", key_type);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
    return ret;
}

static TEE_Result import_key(uint32_t key_type, uint32_t key_size, uint32_t key_format,
    const struct kms_buffer_data *in_key, struct kms_buffer_data *key_blob)
{
    TEE_ObjectHandle key_obj = NULL;
    TEE_Result ret = TEE_AllocateTransientObject(key_type, key_size, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("import key: Allocate Object fail; ret = 0x%x key type 0x%x key size %u\n", ret, key_type, key_size);
        return ret;
    }
    switch (key_format) {
    case KMS_KEY_FORMAT_PKCS1:
        ret = import_key_format_pkcs1(key_type, in_key, key_obj);
        break;
    case KMS_KEY_FORMAT_RAW:
        ret = import_key_format_raw(key_type, in_key, key_obj);
        break;
    default:
        tloge("import key: unsupport key format 0x%x\n", key_format);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
    if (ret != TEE_SUCCESS) {
        tloge("import key: tee generate key fail, key type 0x%x, key size %u\n", key_type, key_size);
        TEE_FreeTransientObject(key_obj);
        key_obj = NULL;
        return ret;
    }

    struct gp_key_base_info bi = { 0 };
    bi.key_type = key_type;
    bi.key_size = key_size;
    bi.version = KMS_KEY_VERSION_2;
    ret = gp_key_to_buffer(key_obj, &bi, key_blob);
    TEE_FreeTransientObject(key_obj);
    key_obj = NULL;
    if (ret != TEE_SUCCESS)
        tloge("import key: key to buffer fail\n");
    return ret;
}

TEE_Result gp_import_key(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_key,
    struct kms_buffer_data *key_blob)
{
    if (param_set == NULL || param_set->buffer == NULL || key_blob == NULL ||
        key_blob->buffer == NULL || in_key == NULL || in_key->buffer == NULL) {
        tloge("gp import key : input is null\n");
        return TEE_ERROR_READ_DATA;
    }

    uint32_t key_type, key_size;
    TEE_Result ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("gp_import_key: get key type failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = get_key_param(&key_size, KMS_TAG_KEY_SIZE, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("gp_import_key: get key size failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t key_format = KMS_KEY_FORMAT_RAW;
    ret = get_key_param(&key_format, KMS_TAG_KEY_FORMAT, param_set);
    if (ret != TEE_SUCCESS)
        tlogi("gp_import_key: default key format\n");
    uint32_t gp_key_type = key_type_kms_to_gp(key_type);
    if (gp_key_type == INVALID_VALUE) {
        tloge("gp import key unsport key type %u\n", key_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = import_key(gp_key_type, key_size, key_format, in_key, key_blob);
    if (ret != TEE_SUCCESS)
        tloge("gp import key fail\n");
    return ret;
}

static TEE_Result confirm_generic_key_type_by_kdf(uint32_t kdf_type, uint32_t *key_type)
{
    switch (kdf_type) {
    case KMS_KDF_CTR_DRBG_AES_ECB:
        *key_type = TEE_TYPE_AES;
        break;
    case KMS_KDF_AUDI_CTR_LIKE_NIST800_108:
        *key_type = TEE_TYPE_HMAC_SHA256;
        break;
    case KMS_KDF_NIST800_108_CTR:
    case KMS_KDF_NONE:
    default:
        tloge("confirm generic by kdf: unsupported kdf type!\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result gp_kdf_load_key(const struct kms_buffer_data *param_set, TEE_ObjectHandle *key_obj,
    struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_obj == NULL ||
                  key_blob == NULL || key_blob->buffer == NULL);
    if (check) {
        tloge("gp kdf load key: input is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    uint32_t kdf_type;
    struct gp_key_base_info *kbi = (struct gp_key_base_info *)key_blob->buffer;

    if (kbi->key_type == TEE_TYPE_GENERIC_SECRET) {
        ret = get_key_param(&kdf_type, KMS_TAG_KDF_TYPE, param_set);
        if (ret != 0) {
            tloge("gp kdf load key: get kdf type failed\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        ret = confirm_generic_key_type_by_kdf(kdf_type, &(kbi->key_type));
        if (ret != TEE_SUCCESS) {
            tloge("gp kdf load key: confirm generic key failed.\n");
            return ret;
        }
    }
    ret = gp_keyblob_to_key(key_blob, NULL, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("gp kdf load key: keyblob to key fail\n");
        return ret;
    }
    return ret;
}

TEE_Result gp_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *out_key,
    struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || out_key == NULL ||
                  out_key->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL);
    if (check) {
        tloge("export key: input is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t key_type;
    TEE_Result ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, param_set);
    if (ret != 0) {
        tloge("export key: key type is invalid %u\n", key_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle key_obj = NULL;
    ret = gp_keyblob_to_key(key_blob, NULL, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("export key: keyblob to key fail\n");
        return ret;
    }

    switch (key_type) {
    case KMS_KEY_TYPE_RSA_PUBLIC:
        ret = export_rsa_public_key(key_obj, out_key);
        break;
    case KMS_KEY_TYPE_SM2_PUBLIC:
        ret = export_sm2_public_key(key_obj, out_key);
        break;
    case KMS_KEY_TYPE_ECDSA_PUBLIC:
        ret = export_ecdsa_public_key(key_obj, out_key);
        break;
    case KMS_KEY_TYPE_ED25519_PUBLIC:
        ret = export_ed25519_public_key(key_obj, out_key);
        break;
    case KMS_KEY_TYPE_SM4:
    case KMS_KEY_TYPE_AES:
    case KMS_KEY_TYPE_HMAC:
    case KMS_KEY_TYPE_SIP_HASH:
    case KMS_KEY_TYPE_GENERIC:
        ret = export_symmetry_key(key_obj, out_key);
        break;
    default:
        tloge("export key: unsupport key type 0x%x\n", key_type);
        ret = TEE_ERROR_BAD_PARAMETERS;
        break;
    }

    TEE_FreeTransientObject(key_obj);
    return ret;
}

TEE_Result gp_create_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL);
    if (check) {
        tloge("gp create key : input is null\n");
        return TEE_ERROR_READ_DATA;
    }
    uint32_t key_type, key_size;
    TEE_Result ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, param_set);
    if (ret != 0) {
        tloge("gp_create_key: get key type failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = get_key_param(&key_size, KMS_TAG_KEY_SIZE, param_set);
    if (ret != 0) {
        tloge("gp_create_key: get key size failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t gp_key_type = key_type_kms_to_gp(key_type);
    if (gp_key_type == INVALID_VALUE) {
        tloge("gp create key unsport key type %u\n", key_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = create_key(gp_key_type, key_size, key_blob);
    if (ret != TEE_SUCCESS)
        tloge("gp ceate key fail\n");
    return ret;
}

static TEE_Result gcm_dec_finish(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi,
    uint8_t *data, uint32_t data_len)
{
    bool check_fail = (koi == NULL || data == NULL || (koi->alg_version == GCM_V1 &&
        data_len < koi->gcm_tag_len / BYTE_TO_BIT + sizeof(uint32_t)) ||
        (koi->alg_version == GCM_V2 && data_len < koi->gcm_tag_len / BYTE_TO_BIT));
    if (check_fail) {
        tloge("aes gcm dec finish: bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t tag_len;
    if (koi->alg_version == GCM_V1)
        tag_len = *(uint32_t *)(data + data_len - sizeof(uint32_t));
    else
        tag_len = koi->gcm_tag_len / BYTE_TO_BIT;

    check_fail = (tag_len != koi->gcm_tag_len / BYTE_TO_BIT || (koi->alg_version == GCM_V1 &&
        tag_len > data_len - sizeof(uint32_t)) || (koi->alg_version == GCM_V2 && tag_len > data_len));
    if (check_fail) {
        tloge("crypto gcm: final total length %u, tag len %zu check fail\n", data_len, tag_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t out_data_len = koi->out_data->length;
    size_t de_data_len = data_len - tag_len;
    de_data_len -= ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    TEE_Result ret = TEE_AEDecryptFinal(crypto_oper, ((de_data_len == 0) ? NULL : data), de_data_len,
        koi->out_data->buffer, &out_data_len, data + de_data_len, tag_len);
    if (ret != TEE_SUCCESS) {
        tloge("ae decrypt final failed, ret = 0x%x, dec len %zu, tag len %zu\n", ret, de_data_len, tag_len);
        return ret;
    }
    koi->out_data->length = out_data_len;
    return TEE_SUCCESS;
}

TEE_Result crypto_gcm_final_decrypto(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi)
{
    bool check = (koi == NULL || (koi->in_data->buffer == NULL && koi->cache_data.buffer == NULL) ||
        (koi->in_data->buffer == NULL && koi->in_data->length > 0) ||
        (koi->cache_data.buffer == NULL && koi->cache_data.length > 0));
    if (check) {
        tloge("null ptr\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t remain_len = koi->gcm_tag_len / BYTE_TO_BIT;
    remain_len += ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    check = (koi->cache_data.length > remain_len || koi->in_data->length < remain_len - koi->cache_data.length ||
        UINT32_MAX - koi->cache_data.length < koi->in_data->length);
    if (check) {
        tloge("crypto gcm decrypto: invalid length, in len %u, cache len %u, declare remain len %u\n",
            koi->in_data->length, koi->cache_data.length, remain_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = TEE_SUCCESS;
    uint8_t *tmp_final_indata = koi->in_data->buffer;
    if (koi->cache_data.length > 0) {
        tmp_final_indata = TEE_Malloc(koi->cache_data.length + koi->in_data->length, TEE_MALLOC_FILL_ZERO);
        if (tmp_final_indata == NULL) {
            tloge("malloc failed, req len %u\n", koi->cache_data.length + koi->in_data->length);
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        check = (memcpy_s(tmp_final_indata, koi->cache_data.length + koi->in_data->length, koi->cache_data.buffer,
            koi->cache_data.length) != EOK || (koi->in_data->length > 0 && memcpy_s(tmp_final_indata +
            koi->cache_data.length, koi->in_data->length, koi->in_data->buffer, koi->in_data->length) != EOK));
        if (check) {
            tloge("copy data failed, in len %u, cache len %u\n", koi->in_data->length, koi->cache_data.length);
            ret = TEE_ERROR_GENERIC;
            goto release;
        }
    }
    ret = gcm_dec_finish(crypto_oper, koi, tmp_final_indata, koi->cache_data.length + koi->in_data->length);
release:
    if (koi->cache_data.length > 0 && tmp_final_indata != NULL) {
        TEE_Free(tmp_final_indata);
        tmp_final_indata = NULL;
    }
    if (ret != TEE_SUCCESS)
        koi->out_data->length = 0;
    return ret;
}

TEE_Result crypto_gcm_final(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi)
{
    bool check = (crypto_oper == NULL || koi == NULL || koi->in_data == NULL ||
        koi->out_data == NULL || koi->out_data->buffer == NULL || koi->gcm_tag_len > GCM_TAG_MAX_LEN);
    if (check) {
        tloge("crypto gcm final:input is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t tag[GCM_TAG_MAX_LEN / BYTE_TO_BIT] = {0};
    size_t tag_len = sizeof(tag);
    size_t out_data_len = koi->out_data->length;
    errno_t rc;
    TEE_Result ret;
    if (koi->mode == TEE_MODE_ENCRYPT) {
        ret = TEE_AEEncryptFinal(crypto_oper, koi->in_data->buffer, (size_t)koi->in_data->length, koi->out_data->buffer,
            &out_data_len, tag, &tag_len);
        if (ret != TEE_SUCCESS) {
            tloge("crypto gcm:final failed, ret=0x%x, in_len %u\n", ret, koi->in_data->length);
            return ret;
        }
        check = (out_data_len > koi->out_data->length || (koi->alg_version == GCM_V1 &&
            (out_data_len + tag_len + sizeof(uint32_t) > koi->out_data->length)) ||
            (koi->alg_version == GCM_V2 && (out_data_len + tag_len > koi->out_data->length)));
        if (check) {
            tloge("crypto gcm: buffer is not enough %u\n", koi->out_data->length);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        rc = memcpy_s(koi->out_data->buffer + out_data_len, koi->out_data->length - out_data_len, tag, tag_len);
        if (rc != EOK) {
            tloge("crypto gcm: fill tag fail\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (tag_len != koi->gcm_tag_len / BYTE_TO_BIT) {
            tloge("check output tag len failed, output %zu, req %u\n", tag_len, koi->gcm_tag_len / BYTE_TO_BIT);
            return TEE_ERROR_GENERIC;
        }
        if (koi->alg_version == GCM_V1) {
            *(uint32_t *)(koi->out_data->buffer + out_data_len + tag_len) = (uint32_t)tag_len;
            koi->out_data->length = out_data_len + tag_len + sizeof(uint32_t);
        } else {
            koi->out_data->length = out_data_len + tag_len;
        }
    } else {
        ret = crypto_gcm_final_decrypto(crypto_oper, koi);
    }
    return ret;
}

static TEE_Result crypto_gcm(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi)
{
    /* AES GCM Mode doesn't need aad while do AEInit, so that AADLen = 0 */
    TEE_Result ret = TEE_AEInit(crypto_oper, koi->iv.buffer, koi->iv.length, koi->gcm_tag_len, 0, 0);
    if (ret != TEE_SUCCESS) {
        tloge("crypto gcm:AEInit error: %x\n", ret);
        return ret;
    }
    /*
     * Generally AES GCM could support updating AAD again and again before handle input data.
     * KMS has two processe flows for AES GCM -- one step enc/dec operation for small data,
     * multi-step begin/update/finish operations for big data. Different flows call common functions.
     * Because one step operation can not support multiple AAD updating operations, and update interfaces DO NOT accept
     * tag params, here kms only support update AAD once. This data will be updated immediately after KMS_TAG_GCM_AAD
     * TAG received and TEE_AEInit called.
     */
    if (koi->aes_gcm_aad_data.buffer != NULL && koi->aes_gcm_aad_data.length > 0) {
        TEE_AEUpdateAAD(crypto_oper, (void *)koi->aes_gcm_aad_data.buffer, (size_t)koi->aes_gcm_aad_data.length);
        koi->aes_gcm_aad_data.length = 0;
    }
    ret = crypto_gcm_final(crypto_oper, koi);
    return ret;
}

static TEE_Result crypto(struct gp_key_opera_input *koi)
{
    TEE_OperationHandle crypto_oper = NULL;
    TEE_Result ret = TEE_AllocateOperation(&crypto_oper, koi->alg_type, koi->mode, koi->key_size);
    if (ret != TEE_SUCCESS) {
        tloge("crypto: allocate operation fail\n");
        return ret;
    }
    ret = TEE_SetOperationKey(crypto_oper, koi->key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("crypto:set OperationKey fail 0x%x\n", ret);
        goto error_free;
    }

    if (check_is_rsa_alg(koi->alg_type)) {
        ret = crypto_rsa(crypto_oper, koi, false);
    } else if (is_gcm_mode(koi->alg_type)) {
        ret = crypto_gcm(crypto_oper, koi);
    } else {
        if (koi->iv.buffer == NULL) {
            TEE_CipherInit(crypto_oper, NULL, 0);
        } else {
            TEE_CipherInit(crypto_oper, koi->iv.buffer, koi->iv.length);
        }
        size_t out_len = koi->out_data->length;
        ret =
            TEE_CipherDoFinal(crypto_oper, koi->in_data->buffer, koi->in_data->length, koi->out_data->buffer, &out_len);
        if (ret != TEE_SUCCESS) {
            tloge("crypto: fail return = 0x%x, in len %u\n", ret, koi->in_data->length);
            goto error_free;
        }
        koi->out_data->length = out_len;
    }
error_free:
    TEE_FreeOperation(crypto_oper);
    return ret;
}

TEE_Result gp_crypto(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    bool check = (key_blob == NULL || key_blob->buffer == NULL || param_set == NULL || in_data == NULL ||
        in_data->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("gp crypto: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct gp_key_opera_input koi;
    errno_t rc = memset_s(&koi, sizeof(koi), 0, sizeof(koi));
    if (rc != EOK) {
        tloge("gp crypto: clear koi fail\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result ret = init_key_opera_input(&koi, key_blob, param_set, kms_mod);
    if (ret != TEE_SUCCESS) {
        tloge("gp crypto: init key operation input fail\n");
        return ret;
    }
    koi.in_data = in_data;
    koi.out_data = out_data;
    ret = crypto(&koi);
    TEE_FreeTransientObject(koi.key_obj);
    koi.key_obj = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("gp crypto: crypto fail\n");
        return ret;
    }
    return ret;
}

TEE_Result gp_digest(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || in_data == NULL ||
        in_data->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("gp digest: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t kms_alg_type = 0;
    TEE_Result ret = get_key_param(&kms_alg_type, KMS_TAG_OPERATION_ALGORITHM, param_set);
    if (ret != 0) {
        tloge("gp digest: no hash type tag\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t alg_type = alg_type_kms_to_gp(kms_alg_type, 0, 0);
    if (alg_type == INVALID_VALUE) {
        tloge("gp digest:unsport alg 0x%x\n", kms_alg_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = digest(alg_type, in_data, out_data);
    return ret;
}

TEE_Result sign_verify(struct gp_key_opera_input *koi)
{
    bool check = (koi == NULL || koi->in_data == NULL || koi->out_data == NULL || koi->key_obj == NULL);
    if (check) {
        tloge("sign verify: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_OperationHandle operation = NULL;
    struct kms_buffer_data new_in_data = *(koi->in_data);
    TEE_Result ret = sm2_alloc_add_za_data(koi->alg_type, koi->key_obj, &new_in_data);
    if (ret != TEE_SUCCESS) {
        tloge("sign verify: sm2 alloc za data fail\n");
        return ret;
    }

    ret = TEE_AllocateOperation(&operation, koi->alg_type, koi->mode, koi->key_size);
    if (ret != TEE_SUCCESS) {
        tloge("sign verify: alloc operation fail\n");
        goto error_free;
    }

    ret = TEE_SetOperationKey(operation, koi->key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("sign verify: set operation fail\n");
        goto error_free;
    }
    if (koi->mode == TEE_MODE_SIGN) {
        size_t out_len = koi->out_data->length;
        ret = TEE_AsymmetricSignDigest(operation, NULL, 0, new_in_data.buffer, new_in_data.length,
            koi->out_data->buffer, &out_len);
        if (ret != TEE_SUCCESS) {
            tloge("sign verify: sign fail, ret = 0x%x, in len %u\n", ret, new_in_data.length);
            goto error_free;
        }
        koi->out_data->length = out_len;
    } else {
        ret = TEE_AsymmetricVerifyDigest(operation, NULL, 0, new_in_data.buffer, new_in_data.length,
            koi->out_data->buffer, koi->out_data->length);
        if (ret != TEE_SUCCESS) {
            tloge("sign verify: verify fail, ret = 0x%x, len1 %u, len2 %u\n",
                ret, new_in_data.length, koi->out_data->length);
            goto error_free;
        }
    }
error_free:
    if (operation != NULL)
        TEE_FreeOperation(operation);
    sm2_free_alloc_in_data(koi->alg_type, &new_in_data);
    return ret;
}
TEE_Result gp_sign_verify(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    bool check = (key_blob == NULL || key_blob->buffer == NULL || param_set == NULL || in_data == NULL ||
        in_data->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("gp sign verify: input is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct gp_key_opera_input koi;
    errno_t rc = memset_s(&koi, sizeof(koi), 0, sizeof(koi));
    if (rc != EOK) {
        tloge("gp sign verify: clear koi fail\n");
        return TEE_ERROR_GENERIC;
    }
    TEE_Result ret = init_key_opera_input(&koi, key_blob, param_set, kms_mod);
    if (ret != TEE_SUCCESS) {
        tloge("gp sign verify: init key operation input fail\n");
        return ret;
    }
    struct kms_buffer_data hash;
    uint8_t hash_res[MAX_HASH_LEN] = {0};
    if (koi.alg_type == TEE_ALG_ED25519) {
        koi.in_data = in_data;
    } else {
        hash.buffer = hash_res;
        hash.length = MAX_HASH_LEN;
        ret = digest_for_sign_data(&koi, in_data, &hash);
        koi.in_data = &hash;
    }
    koi.out_data = out_data;
    ret = sign_verify(&koi);
    TEE_FreeTransientObject(koi.key_obj);
    koi.key_obj = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("gp sign verify: sign verify fail\n");
        return ret;
    }
    return ret;
}

TEE_Result gp_mac_generate(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    bool check = (key_blob == NULL || key_blob->buffer == NULL || param_set == NULL || in_data == NULL ||
        in_data->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("gp mac generate: input is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct gp_key_opera_input koi;
    errno_t rc = memset_s(&koi, sizeof(koi), 0, sizeof(koi));
    if (rc != EOK) {
        tloge("gp mac generate: clear koi fail\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result ret = init_key_opera_input(&koi, key_blob, param_set, kms_mod);
    if (ret != TEE_SUCCESS) {
        tloge("gp mac generate: init key operation input fail\n");
        return ret;
    }
    koi.in_data = in_data;
    koi.out_data = out_data;

    ret = mac_generate(&koi);
    TEE_FreeTransientObject(koi.key_obj);
    koi.key_obj = NULL;
    if (ret != TEE_SUCCESS)
        tloge("gp mac generate: mac generate fail\n");
    return ret;
}
