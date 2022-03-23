/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: kms kdf function
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-7
 */

#include "kdf.h"
#include "securec.h"
#include "kms_tag_api.h"
#include "kms_pub_def.h"
#include "gp_api_adaptation.h"
#include "tee_log.h"
#define SEPERATE_BYTE_LEN 1
#define CNTER_BYTE_LEN 1U
#define MAX_SYM_KEY_SIZE 32U
#define TARGET_BYTE_LEN 2U

#define HASH_256_LEN 32U

static TEE_Result hash_sha256(const uint8_t *buff, uint32_t buf_len, uint8_t *hash, uint32_t *hash_len)
{
    bool check_fail = (buff == NULL || hash == NULL || hash_len == NULL || *hash_len < HASH_256_LEN);
    if (check_fail) {
        tloge("invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_AllocateOperation(&operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("alloc operation fail, ret = 0x%x\n", ret);
        return ret;
    }
    TEE_DigestUpdate(operation, (void *)buff, (size_t)buf_len);
    size_t tmp_out_len = *hash_len;
    ret = TEE_DigestDoFinal(operation, NULL, (size_t)0, (void *)hash, &tmp_out_len);
    if (ret != TEE_SUCCESS) {
        tloge("digest do final failed\n");
        goto error;
    }
    if (tmp_out_len != HASH_256_LEN) {
        tloge("hash len wrong %zu\n", tmp_out_len);
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    *hash_len = (uint32_t)tmp_out_len;
error:
    if (operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(operation);
        operation = TEE_HANDLE_NULL;
    }
    return ret;
}

static TEE_Result concat_raw_key(TEE_ObjectHandle key_obj, struct kms_buffer_data *out_blob, uint32_t *ctr_offset)
{
    TEE_Result ret;
    size_t out_len = out_blob->length;
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_SECRET_VALUE, out_blob->buffer, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("get key attr failed, ret = 0x%x\n", ret);
        return ret;
    }
    *ctr_offset = (uint32_t)out_len;
    return ret;
}

static TEE_Result concat_buf(uint8_t *buff, uint32_t len, struct kms_buffer_data *out_blob, uint32_t *offset)
{
    bool check = (*offset >= out_blob->length || (len > out_blob->length - *offset));
    if (check) {
        tloge("out buf too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (memcpy_s(out_blob->buffer + (*offset), out_blob->length - (*offset), buff, len) != EOK) {
        tloge("memcpy failed\n");
        return TEE_ERROR_GENERIC;
    }

    *offset += (uint32_t)len;
    return TEE_SUCCESS;
}


static TEE_Result concat_buff_tail(struct kms_buffer_data *label, struct kms_buffer_data *context,
    uint16_t target_len_bits, struct kms_buffer_data *out_blob, uint32_t offset)
{
    const uint8_t seperate = 0;
    const uint8_t i = 1;
    uint32_t local_offset = offset;
    TEE_Result ret = concat_buf((uint8_t *)&i, sizeof(i), out_blob, &local_offset);
    if (ret != TEE_SUCCESS) {
        tloge("contact ctr failed\n");
        return ret;
    }
    ret = concat_buf(label->buffer, label->length, out_blob, &local_offset);
    if (ret != TEE_SUCCESS) {
        tloge("concat label failed\n");
        return ret;
    }
    ret = concat_buf((uint8_t *)(&seperate), sizeof(seperate), out_blob, &local_offset);
    if (ret != TEE_SUCCESS) {
        tloge("concat seperate failed\n");
        return ret;
    }
    ret = concat_buf(context->buffer, context->length, out_blob, &local_offset);
    if (ret != TEE_SUCCESS) {
        tloge("concat context failed\n");
        return ret;
    }
    ret = concat_buf((uint8_t *)&target_len_bits, sizeof(target_len_bits), out_blob, &local_offset);
    if (ret != TEE_SUCCESS) {
        tloge("concat target len in bits failed\n");
        return ret;
    }
    out_blob->length = local_offset;
    return TEE_SUCCESS;
}

static TEE_Result derive_target_key(struct kms_buffer_data *salt_blob, uint8_t loop, struct kms_buffer_data *target,
    uint32_t ctr_offset)
{
    uint8_t i;
    TEE_Result ret;
    if (salt_blob->length <= ctr_offset) {
        tloge("bad buff status\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    for (i = 1; i <= loop; i++) {
        salt_blob->buffer[ctr_offset] = i;
        uint8_t hash_res[SHA256_BYTES] = { 0 };
        uint32_t hash_buff_len = SHA256_BYTES;
        ret = hash_sha256(salt_blob->buffer, salt_blob->length, hash_res, &hash_buff_len);
        if (ret != TEE_SUCCESS) {
            tloge("hash fail, ret = 0x%x\n", ret);
            return ret;
        }
        uint32_t target_left_len = target->length - (i - 1) * SHA256_BYTES;
        uint32_t copy_len = ((target_left_len > hash_buff_len) ? hash_buff_len : target_left_len);
        if (memcpy_s(target->buffer + (i - 1) * SHA256_BYTES, target_left_len, hash_res, copy_len) != EOK) {
            tloge("copy hash failed\n");
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

/*
 * This kdf is defined by audi.
 * insert ki before counter 'i' like NIST800_108, set SHA256 as a PRF
 * For (i = to Ceiling[L/h])
 *    K(i) = SHA256(Ki || [i]_2 || Label || 0x00 || Context || [L]_2),
 *    result(i)= result(i-1) || K(i)
 * Return Ko = leftmost L/8 bytes of result(n)
 */
TEE_Result audi_like_nist800_108_ctr_kdf(TEE_ObjectHandle key_obj, enum kms_key_algorithm prf,
    struct kms_buffer_data *label, struct kms_buffer_data *context, struct kms_buffer_data *target)
{
    const struct prf_len support_prf = { KMS_ALG_SHA256, SHA256_BYTES };
    if (support_prf.prf != prf) {
        tloge("unsupported PRF %u\n", prf);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (key_obj == TEE_HANDLE_NULL || target == NULL || target->buffer == NULL || target->length == 0 ||
        target->length >= ((1 << (TARGET_BYTE_LEN * BYTE_TO_BIT)) / BYTE_TO_BIT) || label == NULL ||
        label->buffer == NULL || label->length == 0 || context == NULL || context->buffer == NULL ||
        context->length == 0);
    if (check) {
        tloge("bad params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint16_t loop = (target->length + support_prf.len - 1) / support_prf.len;
    if (loop > (uint16_t)((CNTER_BYTE_LEN << BYTE_TO_BIT) - 1)) {
        tloge("loop %u too large\n", loop);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t tmp_buf[MAX_SALT_BUFFER] = { 0 };
    struct kms_buffer_data buf_blob = { MAX_SALT_BUFFER, tmp_buf };
    uint32_t ctr_offset = 0;
    TEE_Result ret = concat_raw_key(key_obj, &buf_blob, &ctr_offset);
    if (ret != TEE_SUCCESS) {
        tloge("fill raw key failed\n");
        return ret;
    }
    ret = concat_buff_tail(label, context, (uint16_t)(target->length * BYTE_TO_BIT), &buf_blob, ctr_offset);
    if (ret != TEE_SUCCESS) {
        tloge("concat tail buff failed\n");
        goto release;
    }
    ret = derive_target_key(&buf_blob, (uint8_t)loop, target, ctr_offset);
    if (ret != TEE_SUCCESS) {
        tloge("derive target key failed\n");
        goto release;
    }
release:
    (void)memset_s(buf_blob.buffer, buf_blob.length, 0x0, buf_blob.length);
    return ret;
}

static TEE_Result kdf_by_ctr_drbg(TEE_ObjectHandle key_obj, struct kms_buffer_data *in_data,
    struct kms_buffer_data *iv, uint32_t tee_mode, struct kms_buffer_data *out_data)
{
    TEE_OperationHandle crypto_oper = NULL;
    TEE_Result ret = TEE_AllocateOperation(&crypto_oper, TEE_ALG_AES_ECB_NOPAD, tee_mode, KEYBLOB_CRYPTO_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("kdf by aes ecb: allocate operation fail\n");
        return ret;
    }
    ret = TEE_SetOperationKey(crypto_oper, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("kdf by aes ecb: set OperationKey fail 0x%x\n", ret);
        TEE_FreeOperation(crypto_oper);
        return ret;
    }
    TEE_CipherInit(crypto_oper, iv->buffer, iv->length);
    size_t out_len = out_data->length;
    ret = TEE_CipherDoFinal(crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &out_len);
    TEE_FreeOperation(crypto_oper);
    crypto_oper = NULL;
    if (ret != TEE_SUCCESS || out_len > out_data->length) {
        tloge("kdf by aes ecb: fail return = 0x%x, in len %u\n", ret, in_data->length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    out_data->length = out_len;
    return TEE_SUCCESS;
}

/* output is Aes_ecb(ki, (label || 0x00 || context)) */
static TEE_Result kdf_ctr_drbg(TEE_ObjectHandle key_obj, struct kms_buffer_data *label,
    struct kms_buffer_data *context, struct kms_buffer_data *target)
{
    const uint8_t seperate = 0;
    uint8_t tmp_buf[AES_BYTES] = { 0 };
    struct kms_buffer_data tmp_key = { AES_BYTES, tmp_buf };

    uint32_t offset = 0;
    TEE_Result ret = concat_buf(label->buffer, label->length, &tmp_key, &offset);
    if (ret != TEE_SUCCESS) {
        tloge("kdf ctr drbg: concat label failed\n");
        return ret;
    }
    ret = concat_buf((uint8_t *)(&seperate), sizeof(seperate), &tmp_key, &offset);
    if (ret != TEE_SUCCESS) {
        tloge("kdf ctr drbg: concat seperate failed\n");
        return ret;
    }
    ret = concat_buf(context->buffer, context->length, &tmp_key, &offset);
    if (ret != TEE_SUCCESS) {
        tloge("kdf ctr drbg: concat context failed\n");
        return ret;
    }
    /* perform aes_ecb(ki, (label || 0x00 || context)) */
    struct kms_buffer_data iv = { 0, NULL };
    ret = kdf_by_ctr_drbg(key_obj, &tmp_key, &iv, TEE_MODE_ENCRYPT, target);
    if (ret != TEE_SUCCESS) {
        tloge("derive key with aes key mode failed!\n");
        return ret;
    }
    return ret;
}

TEE_Result kdf_implement_algo(const struct kms_buffer_data *param_set, const TEE_ObjectHandle key_obj,
    struct kms_buffer_data *out_key)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_obj == NULL ||
        out_key == NULL || out_key->buffer == NULL);
    if (check) {
        tloge("kdf implement algorithm: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }

    uint32_t kdf_type;
    struct kms_buffer_data label = { 0, NULL };
    struct kms_buffer_data context = { 0, NULL };
    TEE_Result ret = get_key_param(&kdf_type, KMS_TAG_KDF_TYPE, param_set);
    if (ret != 0) {
        tloge("kdf implement algo: get kdf type failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = get_key_param(&label, KMS_TAG_KDF_LABEL, param_set);
    if (ret != 0) {
        tloge("kdf implement algo: get kdf label failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = get_key_param(&context, KMS_TAG_KDF_CONTEXT, param_set);
    if (ret != 0) {
        tloge("kdf implement algo: get kdf context failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (kdf_type) {
    case KMS_KDF_CTR_DRBG_AES_ECB:
        ret = kdf_ctr_drbg(key_obj, &label, &context, out_key);
        break;
    case KMS_KDF_AUDI_CTR_LIKE_NIST800_108:
        ret = audi_like_nist800_108_ctr_kdf(key_obj, KMS_ALG_SHA256, &label, &context, out_key);
        break;
    case KMS_KDF_NIST800_108_CTR:
    case KMS_KDF_NONE:
    default:
        tloge("unsupported kdf algorithm type!\n");
        ret = KMS_ERROR_UNSUPPORTED_KDF;
        break;
    }
    if (ret != TEE_SUCCESS) {
        tloge("kdf implement algorithm: implement 0x%x algorithm failed!\n", kdf_type);
        return ret;
    }
    return ret;
}
