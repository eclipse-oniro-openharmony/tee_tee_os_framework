/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "gp_api_adaptation.h"
#include "kms_pub_def.h"
#include "securec.h"
#include "tee_log.h"
#include <crypto_hal_derive_key.h>

static TEE_Result fill_factor(const char *fix_factor, const struct kms_buffer_data *derived_factor,
    uint8_t *factor_buff, uint32_t *factor_len)
{
    errno_t rc = memcpy_s(factor_buff, *factor_len, fix_factor, strlen(fix_factor));
    if (rc != EOK) {
        tloge("fill factor: copy fix factor fail\n");
        return TEE_ERROR_GENERIC;
    }
    if (derived_factor != NULL && derived_factor->buffer != NULL &&
        derived_factor->length < DERIVER_FACTOR_MAX_LEN) {
        rc = memcpy_s(factor_buff + strlen(fix_factor), *factor_len - strlen(fix_factor),
                      derived_factor->buffer, derived_factor->length);
        if (rc != EOK) {
            tloge("fill factor: copy fix factor fail\n");
            return TEE_ERROR_GENERIC;
        }
        *factor_len = derived_factor->length + strlen(fix_factor);
    } else {
        tlogd("fill factor:derived_factor is invalid\n");
        *factor_len = strlen(fix_factor);
    }

    return TEE_SUCCESS;
}

static TEE_Result get_derived_key(uint8_t *factor_buff, uint32_t factor_len, uint32_t key_type, uint32_t key_size,
    TEE_ObjectHandle *key_obj)
{
    uint8_t crypto_key[KEYBLOB_CRYPTO_KEY_LEN] = { 0 };

    uint32_t derive_type = CRYPTO_TYPE_HMAC_SHA256;
    struct memref_t salt = {0};
    salt.buffer = (uintptr_t)factor_buff;
    salt.size = factor_len;

    struct memref_t cmac = {0};
    cmac.buffer = (uintptr_t)crypto_key;
    cmac.size = KEYBLOB_CRYPTO_KEY_LEN;

    TEE_Result ret = (TEE_Result)tee_crypto_derive_root_key(derive_type, &salt, &cmac, 1);
    if (ret != TEE_SUCCESS) {
        tloge("get derived key: derive key from root key failed 0x%x\n", ret);
        return ret;
    }

    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, crypto_key, KEYBLOB_CRYPTO_KEY_LEN);

    ret = TEE_AllocateTransientObject(key_type, key_size, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("derived key: alloc key fail, ret = 0x%x\n", ret);
        return ret;
    }

    ret = TEE_PopulateTransientObject(*key_obj, &attr, 1);
    if (ret != TEE_SUCCESS) {
        tloge("derived key: put key to obj fail, ret = 0x%x\n", ret);
        TEE_FreeTransientObject(*key_obj);
        *key_obj = NULL;
        return ret;
    }
    (*key_obj)->ObjectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
    return ret;
}

static TEE_Result crypto_by_aes_cbc_pkcs5(TEE_ObjectHandle key_obj, struct kms_buffer_data *in_data,
    struct kms_buffer_data *iv, uint32_t tee_mode, struct kms_buffer_data *out_data)
{
    TEE_OperationHandle crypto_oper = NULL;
    TEE_Result ret = TEE_AllocateOperation(&crypto_oper, TEE_ALG_AES_CBC_PKCS5, tee_mode, KEYBLOB_CRYPTO_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("crypto by aes cbc pkcs5: allocate operation fail\n");
        return ret;
    }
    ret = TEE_SetOperationKey(crypto_oper, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("crypto by aes cbc pkcs5: set OperationKey fail 0x%x\n", ret);
        TEE_FreeOperation(crypto_oper);
        return ret;
    }
    TEE_CipherInit(crypto_oper, iv->buffer, iv->length);
    size_t out_len = out_data->length;
    ret = TEE_CipherDoFinal(crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &out_len);
    TEE_FreeOperation(crypto_oper);
    crypto_oper = NULL;
    if (ret != TEE_SUCCESS || out_len > out_data->length) {
        tloge("crypto by aes cbc pkcs5: fail return = 0x%x, in len %u\n", ret, in_data->length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    out_data->length = out_len;
    return TEE_SUCCESS;
}

static TEE_Result derived_key_by_factor(const char *fix_factor, const struct kms_buffer_data *derived_factor,
    uint32_t key_type, uint32_t key_size, TEE_ObjectHandle *key_obj)
{
    uint8_t factor_buff[DERIVER_FACTOR_MAX_LEN] = { 0 };
    uint32_t factor_len = DERIVER_FACTOR_MAX_LEN;

    TEE_Result ret = fill_factor(fix_factor, derived_factor, factor_buff, &factor_len);
    if (ret != TEE_SUCCESS) {
        tloge("derived key by factor: fill factor fail\n");
        return ret;
    }
    /* derive key from root key */
    ret = get_derived_key(factor_buff, factor_len, key_type, key_size, key_obj);
    if (ret != TEE_SUCCESS)
        tloge("derived key by factor: derived key fail\n");

    return ret;
}

static TEE_Result crypto_key_buff(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *derived_factor,
    uint32_t tee_mode, struct kms_buffer_data *out_data)
{
    TEE_ObjectHandle key_obj = NULL;
    const char *fix_factor = "tee_kms_derived_for_crypto_key_blob";

    TEE_Result ret = derived_key_by_factor(fix_factor, derived_factor, TEE_TYPE_AES, KEYBLOB_CRYPTO_KEY_SIZE, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("crypto key buff: derived key by factor fail\n");
        return ret;
    }
    struct gp_key_base_info *bi = (struct gp_key_base_info *)key_blob->buffer;
    struct kms_buffer_data in_data;
    in_data.buffer = key_blob->buffer + sizeof(*bi);
    in_data.length = key_blob->length - sizeof(*bi);
    if (tee_mode == TEE_MODE_ENCRYPT)
        TEE_GenerateRandom(bi->iv, FIX_IV_LEN);
    struct kms_buffer_data iv;
    iv.buffer = bi->iv;
    iv.length = FIX_IV_LEN;
    ret = crypto_by_aes_cbc_pkcs5(key_obj, &in_data, &iv, tee_mode, out_data);
    if (ret != TEE_SUCCESS)
        tloge("crypto key buff:crypto by aes fail, ret = 0x%x\n", ret);
    TEE_FreeTransientObject(key_obj);
    return ret;
}

static TEE_Result insecure_rsa_pub_e_check(TEE_ObjectHandle key_obj)
{
    if (key_obj == NULL || key_obj->ObjectInfo == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    if (key_obj->ObjectInfo->objectType != TEE_TYPE_RSA_PUBLIC_KEY &&
        key_obj->ObjectInfo->objectType != TEE_TYPE_RSA_KEYPAIR)
        return TEE_SUCCESS;
    uint8_t e[MAX_RSA_KEY_SIZE_BYTE] = { 0 };
    size_t e_len = sizeof(e);
    TEE_Result ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, e, &e_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exponent failed\n");
        return ret;
    }
    if (e_len == 0) {
        tloge("e len is zero\n");
        return TEE_ERROR_NOT_SUPPORTED;
    } else if (e_len < CONST_RSA_PUB_E_SIZE_BYTE) {
        tlogw("Warning: insecure rsa pub exponent, e_len %u\n", e_len);
    } else {
        uint8_t e_min[MAX_RSA_KEY_SIZE_BYTE] = { 0 };
        uint32_t offset = e_len - CONST_RSA_PUB_E_SIZE_BYTE; /* min rsa pub e = 0x01,0x00,0x001 */
        e_min[offset] = 0x01;
        offset++;
        e_min[offset] = 0x00;
        offset++;
        e_min[offset] = 0x01;
        if (TEE_MemCompare(e, e_min, e_len) < 0)
            tlogw("Warning: insecure rsa pub exponent, e_len %u\n", e_len);
    }
    return TEE_SUCCESS;
}

static TEE_Result key_object_to_buffer(const TEE_ObjectHandle key_obj, uint8_t *kb, uint32_t *buffer_len)
{
    uint32_t len = 0;
    uint32_t attr_id;
    uint8_t *value = NULL;
    uint32_t attri_count = key_obj->attributesLen;
    uint32_t i;
    uint32_t data_len = 0;
    /* tlv data, buffer->length not than 4k, it check in invoke check. */
    for (i = 0; i < attri_count; i++) {
        attr_id = key_obj->Attribute[i].attributeID;
        /* type, len */
        if ((data_len + sizeof(attr_id) + sizeof(len)) > *buffer_len) {
            tloge("key object to buffer: buffer len is too short, need %u\n", data_len);
            return TEE_ERROR_SHORT_BUFFER;
        }
        *(uint32_t *)(kb + data_len) = attr_id;
        data_len += sizeof(attr_id);
        if (object_attr_type(attr_id) == OBJECT_ATTR_BUFFER) {
            value = key_obj->Attribute[i].content.ref.buffer;
            len = key_obj->Attribute[i].content.ref.length;
        } else {
            value = (uint8_t *)&key_obj->Attribute[i].content.value;
            len = sizeof(key_obj->Attribute[i].content.value);
        }
        *(uint32_t *)(kb + data_len) = len;
        data_len += sizeof(len);
        /* store buffer or value(value) */
        if ((len > *buffer_len) || (data_len + len > *buffer_len) ||
            (memcpy_s(kb + data_len, *buffer_len - data_len, value, len) != EOK)) {
            tloge("key object to buffer: copy value failed\n");
            return TEE_ERROR_SHORT_BUFFER;
        }
        data_len += len;
        tlogd("key object 0x%x to buffer: buf_len is %d\n", attr_id, data_len);
    }
    *buffer_len = data_len;
    if (insecure_rsa_pub_e_check(key_obj) != TEE_SUCCESS) {
        tloge("check rsa pub e failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result gp_key_to_buffer(const TEE_ObjectHandle key_obj, struct gp_key_base_info *bi,
    struct kms_buffer_data *key_blob)
{
    uint8_t *kb = key_blob->buffer;
    uint32_t buffer_len = key_blob->length;
    if (buffer_len < sizeof(*bi) || memcpy_s(kb, buffer_len, bi, sizeof(*bi)) != EOK) {
        tloge("gp key to keyblob: copy fail\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    buffer_len -= sizeof(*bi);
    kb += sizeof(*bi);
    TEE_Result ret = key_object_to_buffer(key_obj, kb, &buffer_len);
    if (ret != TEE_SUCCESS) {
        tloge("gp key to keyblob: key obj to buffer fail\n");
        return ret;
    }
    key_blob->length = buffer_len + sizeof(*bi);
    return TEE_SUCCESS;
}

static TEE_Result gp_buffer_to_key_obj(const uint8_t *buffer, uint32_t buffer_len, TEE_ObjectHandle key_obj)
{
    uint32_t read_size = 0;
    uint32_t attr_id;
    uint32_t len;
    uint8_t *dest_buffer = NULL;
    uint32_t dest_len;
    uint32_t i;
    for (i = 0; i < key_obj->attributesLen; i++) {
        if (read_size + sizeof(attr_id) + sizeof(len) > buffer_len) {
            tloge("buffer to key: read len %u, buffer len %u\n", read_size, buffer_len);
            return TEE_ERROR_READ_DATA;
        }
        attr_id = *(uint32_t *)(buffer + read_size);
        read_size += sizeof(attr_id);
        len = *(uint32_t *)(buffer + read_size);
        read_size += sizeof(len);
        if (attr_id != key_obj->Attribute[i].attributeID || (read_size + len) > buffer_len) {
            tloge("buffer to key: key type not match key attribute 0x%x\n", attr_id);
            return TEE_ERROR_READ_DATA;
        }

        if (object_attr_type(attr_id) == OBJECT_ATTR_BUFFER) {
            dest_buffer = key_obj->Attribute[i].content.ref.buffer;
            dest_len = key_obj->Attribute[i].content.ref.length;
            key_obj->Attribute[i].content.ref.length = len;
        } else {
            dest_buffer = (uint8_t *)&key_obj->Attribute[i].content.value;
            dest_len = sizeof(key_obj->Attribute[i].content.value);
        }
        if (len > (buffer_len - read_size) || memcpy_s(dest_buffer, dest_len, buffer + read_size, len) != EOK) {
            tloge("buffer to key: copy attribute 0x%x fail, dest %u src %u\n", attr_id, dest_len, len);
            return TEE_ERROR_READ_DATA;
        }
        read_size += len;
    }
    key_obj->ObjectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
    if (insecure_rsa_pub_e_check(key_obj) != TEE_SUCCESS) {
        tloge("check rsa pub e failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result gp_keyblob_to_key(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *derived_factor,
    TEE_ObjectHandle *key_obj)
{
    if (key_blob->length < sizeof(struct gp_key_base_info)) {
        tloge("gp keyblob to key: buffer is too short %u\n", key_blob->length);
        return TEE_ERROR_READ_DATA;
    }
    struct gp_key_base_info *bi = (struct gp_key_base_info *)key_blob->buffer;
    if (TEE_AllocateTransientObject(bi->key_type, bi->key_size, key_obj) != TEE_SUCCESS) {
        tloge("gp keyblob to key: alloc key fail key type %u key size %u\n", bi->key_type, bi->key_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    if (bi->version >= KMS_KEY_VERSION_2) {
        ret = gp_buffer_to_key_obj(key_blob->buffer + sizeof(*bi), key_blob->length - sizeof(*bi), *key_obj);
    } else {
        uint8_t key_data[GP_MAX_KEY_BUFFER] = { 0 };
        struct kms_buffer_data out_data = { GP_MAX_KEY_BUFFER, key_data };
        ret = crypto_key_buff(key_blob, derived_factor, TEE_MODE_DECRYPT, &out_data);
        if (ret != TEE_SUCCESS) {
            tloge("gp keyblob to key: crypto key buffer fail\n");
            TEE_FreeTransientObject(*key_obj);
            *key_obj = NULL;
            return ret;
        }
        ret = gp_buffer_to_key_obj(out_data.buffer, out_data.length, *key_obj);
    }
    if (ret != TEE_SUCCESS) {
        tloge("gp keyblob to key: buffer to key fail\n");
        TEE_FreeTransientObject(*key_obj);
        *key_obj = NULL;
    }
    return ret;
}

TEE_Result mac_generate(struct gp_key_opera_input *koi)
{
    TEE_OperationHandle operation = NULL;
    TEE_Result ret = TEE_AllocateOperation(&operation, koi->alg_type, koi->mode, koi->key_size);
    if (ret != TEE_SUCCESS) {
        tloge("mac generate: alloc operation fail\n");
        return ret;
    }
    ret = TEE_SetOperationKey(operation, koi->key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("mac generate: set operation fail\n");
        goto error_free;
    }
    /* if operation already set key, this not need set again */
    TEE_MACInit(operation, NULL, 0);

    size_t out_len = koi->out_data->length;
    ret = TEE_MACComputeFinal(operation, koi->in_data->buffer, koi->in_data->length, koi->out_data->buffer, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("mac final error, ret:0x%x\n", ret);
        goto error_free;
    }
    koi->out_data->length = out_len;
error_free:
    if (operation != NULL)
        TEE_FreeOperation(operation);
    return ret;
}

TEE_Result key_blob_crypto(const struct kms_buffer_data *key_blob, uint32_t tee_mode, struct kms_buffer_data *out_data)
{
    bool check = (key_blob == NULL || key_blob->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("key blob crypto: bad input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_ObjectHandle key_obj = NULL;
    const char *fix_factor = "tee_kms_derived_for_crypto_key_blob";

    struct kms_key_base_info *key_base_info = (struct kms_key_base_info *)key_blob->buffer;
    if (tee_mode == TEE_MODE_ENCRYPT)
        TEE_GenerateRandom(key_base_info->iv, FIX_IV_LEN);
    /* use key_base_info from key_type to total_length as derived_factor */
    struct kms_buffer_data derived_factor;
    derived_factor.buffer = (uint8_t *)key_base_info + sizeof(key_base_info->mac);
    derived_factor.length = sizeof(*key_base_info) - sizeof(key_base_info->mac) - sizeof(key_base_info->total_length);
    TEE_Result ret = derived_key_by_factor(fix_factor, &derived_factor,
        TEE_TYPE_AES, KEYBLOB_CRYPTO_KEY_SIZE, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("crypto key buff: derived key by factor fail\n");
        return ret;
    }
    struct kms_buffer_data in_data;
    in_data.buffer = key_base_info->keyblob_body;
    in_data.length = key_base_info->total_length - sizeof(*key_base_info);
    struct kms_buffer_data iv;
    iv.buffer = key_base_info->iv;
    iv.length = FIX_IV_LEN;
    ret = crypto_by_aes_cbc_pkcs5(key_obj, &in_data, &iv, tee_mode, out_data);
    if (ret != TEE_SUCCESS)
        tloge("crypto key buff:crypto by aes fail, ret = 0x%x\n", ret);
    TEE_FreeTransientObject(key_obj);
    return ret;
}

TEE_Result key_blob_mac(struct kms_buffer_data *derived_factor, struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    bool check = (in_data == NULL || in_data->buffer == NULL || out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("key blob mac: bad input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle key_obj = NULL;
    const char *fix_factor = "tee_kms_derived_for_hmac_key_blob";

    TEE_Result ret = derived_key_by_factor(fix_factor, derived_factor, TEE_TYPE_HMAC_SHA256, KEYBLOB_MAC_KEY_SIZE,
        &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("crypto key buff: derived key by factor fail\n");
        return ret;
    }

    struct gp_key_opera_input koi = { 0 };
    koi.in_data = in_data;
    koi.out_data = out_data;
    koi.key_obj = key_obj;
    koi.alg_type = TEE_ALG_HMAC_SHA256;
    koi.mode = TEE_MODE_MAC;
    koi.key_size = KEYBLOB_MAC_KEY_SIZE;
    ret = mac_generate(&koi);
    TEE_FreeTransientObject(key_obj);
    key_obj = NULL;
    if (ret != TEE_SUCCESS)
        tloge("key blob mac: mac generate fail\n");

    return ret;
}
