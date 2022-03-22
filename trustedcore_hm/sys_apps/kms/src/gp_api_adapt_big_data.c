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
#include "kms_key_node.h"
#include "gp_api_adapt_util.h"

void free_koi_cache(struct gp_key_opera_input *koi)
{
    if (koi != NULL) {
        TEE_Free(koi->cache_data.buffer);
        koi->cache_data.buffer = NULL;
        koi->cache_data.length = 0;
    }
}

void gp_key_opera_free(struct gp_key_opera_input *koi)
{
    if (koi == NULL)
        return;
    if (koi->key_obj != NULL) {
        TEE_FreeTransientObject(koi->key_obj);
        koi->key_obj = NULL;
    }
    if (koi->crypto_oper != NULL) {
        TEE_FreeOperation(koi->crypto_oper);
        koi->crypto_oper = NULL;
    }
    free_koi_cache(koi);
    TEE_Free(koi);
}

static TEE_Result gp_init_operation(const struct kms_buffer_data *key_buffer, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct gp_key_opera_input *koi)
{
    TEE_Result ret = init_key_opera_input(koi, key_buffer, param_set, kms_mod);
    if (ret != TEE_SUCCESS) {
        tloge("gp init operation: init key operation input fail\n");
        return ret;
    }

    TEE_OperationHandle crypto_oper = NULL;
    uint32_t alg = koi->alg_type;
    uint32_t mod = koi->mode;
    uint32_t key_size = koi->key_size;
    /* sign or verify except ed25519update should operation to hash, and use key object in finish */
    if (alg != TEE_ALG_ED25519 && (koi->mode == TEE_MODE_SIGN || koi->mode == TEE_MODE_VERIFY)) {
        alg = alg_type_kms_to_gp(0, koi->hash_type, 0);
        if (alg == INVALID_VALUE) {
            tloge("unsupported kms hash 0x%x\n", koi->hash_type);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        mod = TEE_MODE_DIGEST;
        key_size = 0;
    }
    ret = TEE_AllocateOperation(&crypto_oper, alg, mod, key_size);
    if (ret != TEE_SUCCESS) {
        tloge("gp init operation: allocate operation fail\n");
        goto error_free;
    }
    if (koi->mode == TEE_MODE_SIGN || koi->mode == TEE_MODE_VERIFY || koi->mode == TEE_MODE_DIGEST) {
        koi->crypto_oper = crypto_oper;
        return TEE_SUCCESS;
    }

    ret = TEE_SetOperationKey(crypto_oper, koi->key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("gp init operation:set OperationKey fail 0x%x\n", ret);
        TEE_FreeOperation(crypto_oper);
        crypto_oper = NULL;
        goto error_free;
    }
    koi->crypto_oper = crypto_oper;
error_free:
    if (koi->key_obj != NULL) {
        TEE_FreeTransientObject(koi->key_obj);
        koi->key_obj = NULL;
    }
    return ret;
}

static TEE_Result gp_crypto_begin(struct gp_key_opera_input *koi)
{
    TEE_Result ret = TEE_SUCCESS;
    uint8_t *iv = (koi->iv.buffer == NULL ? NULL : koi->iv.buffer);
    uint32_t iv_len = (koi->iv.buffer == NULL ? 0 : koi->iv.length);
    if (is_gcm_mode(koi->alg_type)) {
        ret = TEE_AEInit(koi->crypto_oper, iv, iv_len, koi->gcm_tag_len, 0, 0);
        if (ret != TEE_SUCCESS) {
            tloge("crypto begin: AE init, ret = 0x%x\n", ret);
            return ret;
        }
        /*
         * kms only support update AAD once. The AAD data will be updated immediately after KMS_TAG_GCM_AAD
         * TAG received and TEE_AEInit called.
         */
        if (koi->aes_gcm_aad_data.buffer != NULL && koi->aes_gcm_aad_data.length > 0) {
            TEE_AEUpdateAAD(koi->crypto_oper, (void *)koi->aes_gcm_aad_data.buffer,
                (size_t)koi->aes_gcm_aad_data.length);
            koi->aes_gcm_aad_data.length = 0;
        }
    } else {
        TEE_CipherInit(koi->crypto_oper, iv, iv_len);
    }
    return ret;
}

static TEE_Result gp_begin_by_mod(const struct kms_buffer_data *key_buffer, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct gp_key_opera_input *koi)
{
    TEE_Result ret = gp_init_operation(key_buffer, param_set, kms_mod, koi);
    if (ret != TEE_SUCCESS) {
        tloge("gp begin: init operation fail\n");
        return ret;
    }
    switch (koi->mode) {
    case TEE_MODE_ENCRYPT:
    case TEE_MODE_DECRYPT:
        if (!check_is_rsa_alg(koi->alg_type))
            ret = gp_crypto_begin(koi);
        break;
    case TEE_MODE_DIGEST:
        break;
    case TEE_MODE_SIGN:
    case TEE_MODE_VERIFY:
        if (koi->alg_type == TEE_ALG_SM2_DSA_SM3)
            ret = sm2_begin(koi);
        break;
    case TEE_MODE_MAC:
        TEE_MACInit(koi->crypto_oper, NULL, 0);
        break;
    default:
        tloge("unsupport mod %u\n", koi->mode);
        ret = TEE_ERROR_BAD_PARAMETERS;
        break;
    }
    return ret;
}

/* key_buffer can null, when do hash */
TEE_Result gp_begin(const struct kms_buffer_data *key_buffer, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct kms_buffer_data *opt_handle)
{
    bool check = (param_set == NULL || param_set->buffer == NULL ||
                  opt_handle == NULL || opt_handle->buffer == NULL);
    if (check) {
        tloge("gp begin: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_key_node *key_node = NULL;
    struct gp_key_opera_input *koi = TEE_Malloc(sizeof(struct gp_key_opera_input), TEE_MALLOC_FILL_ZERO);
    if (koi == NULL) {
        tloge("gp begin: malloc fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_Result ret = gp_begin_by_mod(key_buffer, param_set, kms_mod, koi);
    if (ret != TEE_SUCCESS) {
        tloge("gp begin: init operation fail\n");
        goto error_free;
    }
    key_node = alloc_init_key_node(ENGINE_TYPE_GP);
    if (key_node == NULL) {
        tloge("gp begin:alloc key node fail\n");
        ret = TEE_ERROR_GENERIC;
        goto error_free;
    }
    key_node->key_operate = (void *)koi;
    errno_t rc = memcpy_s(opt_handle->buffer, opt_handle->length, &key_node->opt_handle, sizeof(key_node->opt_handle));
    if (rc != EOK) {
        tloge("gp begin: copy handle fail\n");
        ret = TEE_ERROR_GENERIC;
        goto error_free;
    }
    opt_handle->length = sizeof(key_node->opt_handle);
    /* this func must run in last, or if run has error after this fun,
     * need call delete_free_key_node and set key_node to null
     */
    ret = add_key_node(key_node);
    if (ret != TEE_SUCCESS) {
        tloge("gp begin: add key node fail\n");
        goto error_free;
    }
    return TEE_SUCCESS;
error_free:
    gp_key_opera_free(koi);
    koi = NULL;
    if (key_node != NULL) {
        TEE_Free(key_node);
        key_node = NULL;
    }
    return ret;
}

static TEE_Result gp_key_opera_check(struct gp_key_opera_input *koi, uint32_t kms_mod)
{
    uint32_t tee_mod = mod_kms_to_gp(kms_mod);
    if (tee_mod != koi->mode) {
        tloge("gp key opera check:begin and update mod not match %u %u\n", tee_mod, kms_mod);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (koi->crypto_oper == NULL) {
        tloge("gp key opera check:operation is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result cache_in_data(struct gp_key_opera_input *koi)
{
    TEE_Result ret = TEE_SUCCESS;
    bool check_fail = (koi == NULL || koi->in_data == NULL ||
        (koi->in_data->buffer == NULL && koi->in_data->length != 0));
    if (check_fail) {
        tloge("bad parameters\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto error;
    }
    uint32_t max_buf_len = check_is_rsa_alg(koi->alg_type) ? RSA_MAX_CRYPTO_DATA_LEN : UINT32_MAX;
    check_fail = (koi->cache_data.length > max_buf_len || koi->in_data->length > max_buf_len ||
        max_buf_len - koi->cache_data.length < koi->in_data->length);
    if (check_fail) {
        tloge("invalid in data length, %u + %u, max limit %u\n", koi->cache_data.length, koi->in_data->length,
            max_buf_len);
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    uint32_t tmp_len = koi->cache_data.length + koi->in_data->length;
    uint8_t *tmp_buf = NULL;
    if (tmp_len > 0 && koi->in_data->length > 0) {
        tmp_buf = TEE_Malloc(tmp_len, TEE_MALLOC_FILL_ZERO);
        if (tmp_buf == NULL) {
            tloge("malloc failed\n");
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto error;
        }
    }
    check_fail = ((koi->cache_data.length > 0 && koi->in_data->length > 0 && tmp_buf != NULL &&
        memcpy_s(tmp_buf, tmp_len, koi->cache_data.buffer, koi->cache_data.length) != EOK) ||
        (koi->in_data->length > 0 && tmp_buf != NULL && memcpy_s(tmp_buf + koi->cache_data.length,
        tmp_len - koi->cache_data.length, koi->in_data->buffer, koi->in_data->length) != EOK));
    if (check_fail) {
        tloge("cache in data failed, cached %u, in %u\n", koi->cache_data.length, koi->in_data->length);
        TEE_Free(tmp_buf);
        tmp_buf = NULL;
        ret = TEE_ERROR_SHORT_BUFFER;
        goto error;
    }
    if (tmp_buf != NULL) {
        TEE_Free(koi->cache_data.buffer);
        koi->cache_data.buffer = tmp_buf;
    }
    koi->cache_data.length = tmp_len;
    return TEE_SUCCESS;
error:
    free_koi_cache(koi);
    return ret;
}

static TEE_Result aes_gcm_dec_only_cache(struct gp_key_opera_input *koi)
{
    /* total length less than tag len, must be cached, do not update */
    uint32_t remain_len = koi->gcm_tag_len / BYTE_TO_BIT;
    remain_len += ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    bool check_fail = ((koi->in_data->buffer == NULL && koi->in_data->length != 0) ||
        koi->cache_data.buffer == NULL || koi->cache_data.length > remain_len ||
        koi->in_data->length > remain_len - koi->cache_data.length);
    if (check_fail) {
        tloge("null ptr or invalid length: cache len %u, in len %u, remain len %u\n", koi->cache_data.length,
            koi->in_data->length, remain_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (koi->in_data->length != 0 && memcpy_s(koi->cache_data.buffer + koi->cache_data.length, remain_len -
        koi->cache_data.length, koi->in_data->buffer, koi->in_data->length) != EOK) {
        tloge("memcpy cache input failed\n");
        return TEE_ERROR_GENERIC;
    }
    koi->cache_data.length += koi->in_data->length; /* accumulate the length */
    koi->out_data->length = 0;
    return TEE_SUCCESS;
}

static TEE_Result aes_gcm_dec_update_part_cache(struct gp_key_opera_input *koi)
{
    /* total length larger than tag len, but less than (taglen + cache len), update the head part of cache data */
    uint32_t remain_len = koi->gcm_tag_len / BYTE_TO_BIT;
    remain_len += ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    bool check_fail = ((koi->in_data->buffer == NULL && koi->in_data->length != 0) || koi->cache_data.buffer == NULL ||
        koi->cache_data.length > remain_len || koi->in_data->length <= remain_len - koi->cache_data.length ||
        koi->in_data->length > remain_len);
    if (check_fail) {
        tloge("null ptr or invalid length: cache len %u, in len %u, remain len %u\n", koi->cache_data.length,
            koi->in_data->length, remain_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t in_len = koi->in_data->length + koi->cache_data.length - remain_len;
    size_t tmp_out = koi->out_data->length;
    TEE_Result ret = TEE_AEUpdate(koi->crypto_oper, koi->cache_data.buffer, in_len, koi->out_data->buffer,
        &tmp_out);
    if (ret != TEE_SUCCESS) {
        tloge("ae update part cache data failed, ret = 0x%x\n", ret);
        return ret;
    }
    if (koi->cache_data.length > in_len && memmove_s(koi->cache_data.buffer, remain_len,
        koi->cache_data.buffer + in_len, koi->cache_data.length - in_len) != EOK) {
        tloge("copy remain cached data failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (koi->in_data->length > 0 && memmove_s(koi->cache_data.buffer + koi->cache_data.length - in_len, remain_len -
        koi->cache_data.length + in_len, koi->in_data->buffer, koi->in_data->length) != EOK) {
        tloge("copy in data failed\n");
        return TEE_ERROR_GENERIC;
    }
    koi->cache_data.length = koi->cache_data.length + koi->in_data->length - in_len;
    koi->out_data->length = tmp_out;
    return TEE_SUCCESS;
}

static TEE_Result aes_gcm_dec_update_cache(struct gp_key_opera_input *koi)
{
    /* total length larger than (taglen + cache len) update total cache data and possible head part of new in_data */
    uint32_t remain_len = koi->gcm_tag_len / BYTE_TO_BIT;
    remain_len += ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    bool check_fail = ((koi->in_data->buffer == NULL && koi->in_data->length != 0) || koi->cache_data.buffer == NULL ||
        koi->cache_data.length > remain_len || koi->in_data->length <= remain_len);
    if (check_fail) {
        tloge("null ptr or invalid length: cache len %u, in len %u, tag len %u\n", koi->cache_data.length,
            koi->in_data->length, remain_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    size_t tmp_out = 0;
    TEE_Result ret;
    if (koi->cache_data.length != 0) {
        tmp_out = koi->out_data->length;
        ret = TEE_AEUpdate(koi->crypto_oper, koi->cache_data.buffer, koi->cache_data.length, koi->out_data->buffer,
            &tmp_out);
        if (ret != TEE_SUCCESS) {
            tloge("ae update total cache data failed, ret = 0x%x\n", ret);
            return ret;
        }
    }
    size_t out = koi->out_data->length - tmp_out;
    ret = TEE_AEUpdate(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length -
        remain_len, koi->out_data->buffer + tmp_out, &out);
    if (ret != TEE_SUCCESS) {
        tloge("ae update cache data failed, ret = 0x%x\n", ret);
        return ret;
    }
    if (remain_len > 0 && memcpy_s(koi->cache_data.buffer, remain_len, koi->in_data->buffer + koi->in_data->length -
        remain_len, remain_len) != EOK) {
        tloge("cache the tail indata as tag failed\n");
        return TEE_ERROR_GENERIC;
    }
    koi->cache_data.length = remain_len;
    koi->out_data->length = tmp_out + out;
    return TEE_SUCCESS;
}

static TEE_Result aes_gcm_dec_update(struct gp_key_opera_input *koi)
{
    uint32_t remain_len = koi->gcm_tag_len / BYTE_TO_BIT;
    remain_len += ((koi->alg_version == GCM_V1) ? sizeof(uint32_t) : 0);
    bool check = (koi->cache_data.length > remain_len || UINT32_MAX - koi->cache_data.length < koi->in_data->length ||
        (koi->cache_data.buffer == NULL && koi->cache_data.length != 0));
    if (check) {
        tloge("nullptr or invalid length, cached len %u, in len %u\n", koi->cache_data.length, koi->in_data->length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (koi->cache_data.buffer == NULL) {
        koi->cache_data.buffer = TEE_Malloc(remain_len, TEE_MALLOC_FILL_ZERO);
        if (koi->cache_data.buffer == NULL) {
            tloge("malloc taglen %u failed\n", remain_len);
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }
    TEE_Result ret;
    if (koi->in_data->length <= (remain_len - koi->cache_data.length))
        /* total length less than tag len, must be cached, do not update */
        ret = aes_gcm_dec_only_cache(koi);
    else if (koi->in_data->length <= remain_len)
        /* total length larger than tag len, but less than (taglen + cache len), update the head part of cache data */
        ret = aes_gcm_dec_update_part_cache(koi);
    else
        /* total length >= (taglen + cache len), update total cache data and possible head part of new in_data */
        ret = aes_gcm_dec_update_cache(koi);
    if (ret != TEE_SUCCESS) {
        tloge("aes gcm decrypt update failed, ret = 0x%x\n", ret);
        goto error;
    }
    return TEE_SUCCESS;
error:
    TEE_Free(koi->cache_data.buffer);
    koi->cache_data.buffer = NULL;
    koi->cache_data.length = 0;
    koi->out_data->length = 0;
    return ret;
}

static TEE_Result gp_crypto_update(struct gp_key_opera_input *koi)
{
    size_t out_len;
    TEE_Result ret;

    /* rsa en de crypto in out buffer can null */
    if (check_is_rsa_alg(koi->alg_type)) {
        if (koi->out_data != NULL)
            koi->out_data->length = 0;
        return cache_in_data(koi);
    }

    if (koi->out_data == NULL || koi->out_data->buffer == NULL) {
        tloge("gp crypto update:out buffer is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    out_len = koi->out_data->length;
    if (is_gcm_mode(koi->alg_type)) {
        if (koi->mode == TEE_MODE_DECRYPT)
            return aes_gcm_dec_update(koi);
        ret = TEE_AEUpdate(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length, koi->out_data->buffer,
            &out_len);
    } else {
        ret = TEE_CipherUpdate(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length,
            koi->out_data->buffer, &out_len);
    }
    koi->out_data->length = out_len;
    return ret;
}
static TEE_Result gp_update_by_mod(struct gp_key_opera_input *koi)
{
    TEE_Result ret = TEE_SUCCESS;
    switch (koi->mode) {
    case TEE_MODE_ENCRYPT:
    case TEE_MODE_DECRYPT:
        ret = gp_crypto_update(koi);
        break;
    case TEE_MODE_DIGEST:
    case TEE_MODE_SIGN:
    case TEE_MODE_VERIFY:
        koi->out_data->length = 0;
        if (koi->alg_type == TEE_ALG_ED25519)
            ret = cache_in_data(koi);
        else
            TEE_DigestUpdate(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length);
        break;
    case TEE_MODE_MAC:
        TEE_MACUpdate(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length);
        break;
    default:
        tloge("gp update by mod: unsupport mod %u\n", koi->mode);
        ret = TEE_ERROR_BAD_STATE;
        break;
    }
    return ret;
}

static TEE_Result get_and_check_key_node(const struct kms_buffer_data *opt_handle, uint32_t kms_mod,
    struct kms_key_node **node)
{
    uint64_t handle = *(uint64_t *)opt_handle->buffer;
    struct kms_key_node *key_node = NULL;
    TEE_Result ret = get_key_node(handle, &key_node);
    if (ret != TEE_SUCCESS) {
        tloge("get check keynode: can't get keynode by handle 0x%llx\n", handle);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct gp_key_opera_input *koi = (struct gp_key_opera_input *)key_node->key_operate;
    if (koi == NULL || koi->crypto_oper == NULL) {
        tloge("get check keynode: begin may be error, koi is null\n");
        return TEE_ERROR_BAD_STATE;
    }
    ret = gp_key_opera_check(koi, kms_mod);
    if (ret != TEE_SUCCESS) {
        tloge("get check keynode:key operate is invalid, ret = 0x%x\n", ret);
        return TEE_ERROR_NO_DATA;
    }
    *node = key_node;
    return TEE_SUCCESS;
}

TEE_Result gp_update(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    bool check =
        (opt_handle == NULL || opt_handle->length != sizeof(uint64_t) || in_data == NULL || in_data->buffer == NULL);
    if (check) {
        tloge("gp update: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = set_ophandle_state(*(uint64_t *)opt_handle->buffer, USING);
    if (ret != TEE_SUCCESS) {
        tloge("set ophandle state %u failed\n", USING);
        return ret;
    }
    TEE_Result handle_ret;
    struct kms_key_node *key_node = NULL;
    ret = get_and_check_key_node(opt_handle, kms_mod, &key_node);
    if (ret != TEE_SUCCESS) {
        tloge("gp update: key node check error, ret = 0x%x\n", ret);
        goto out;
    }
    struct gp_key_opera_input *koi = (struct gp_key_opera_input *)key_node->key_operate;
    koi->in_data = in_data;
    koi->out_data = out_data;
    ret = gp_update_by_mod(koi);
    if (ret != TEE_SUCCESS) {
        tloge("gp update: update failed, ret = 0x%x\n", ret);
        free_koi_cache(koi);
    }
out:
    handle_ret = set_ophandle_state(*(uint64_t *)opt_handle->buffer, IDLE);
    if (handle_ret != TEE_SUCCESS) {
        tloge("set ophandle state %u failed, handle ret = 0x%x, ret = 0x%x\n", IDLE, handle_ret, ret);
        ret = (ret == TEE_SUCCESS) ? handle_ret : ret;
    }
    return ret;
}

static TEE_Result gp_sign_verify_finish(struct gp_key_opera_input *koi)
{
    TEE_Result ret;
    struct kms_buffer_data hash;
    uint8_t hash_res[MAX_HASH_LEN] = {0};
    if (koi->alg_type != TEE_ALG_ED25519) {
        hash.buffer = hash_res;
        hash.length = MAX_HASH_LEN;
        size_t out_len = MAX_HASH_LEN;
        ret = TEE_DigestDoFinal(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length, hash_res, &out_len);
        if (ret != TEE_SUCCESS) {
            tloge("gp sign verify finish:do hash fail, ret = 0x%x, in len %u\n", ret, koi->in_data->length);
            return ret;
        }
        hash.length = out_len;
        koi->in_data = &hash;
    } else {
        ret = cache_in_data(koi);
        koi->in_data = &(koi->cache_data);
    }
    ret = sign_verify(koi);
    if (ret != TEE_SUCCESS)
        tloge("gp sign verify finish:do sign verify fail, ret = 0x%x\n", ret);
    return ret;
}

static TEE_Result crypto_rsa_finish(struct gp_key_opera_input *koi)
{
    TEE_Result ret = cache_in_data(koi);
    if (ret != TEE_SUCCESS) {
        tloge("rsa finish: update data fail\n");
        return ret;
    }
    ret = crypto_rsa(koi->crypto_oper, koi, true);
    if (ret != 0)
        tloge("rsa finish: crypto fail\n");
    return ret;
}
static TEE_Result gp_crypto_finish(struct gp_key_opera_input *koi)
{
    TEE_Result ret;
    size_t out_len = koi->out_data->length;
    if (check_is_rsa_alg(koi->alg_type)) {
        ret = crypto_rsa_finish(koi);
    } else if (is_gcm_mode(koi->alg_type)) {
        ret = crypto_gcm_final(koi->crypto_oper, koi);
    } else {
        ret = TEE_CipherDoFinal(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length, koi->out_data->buffer,
            &out_len);
        koi->out_data->length = out_len;
    }
    if (ret != TEE_SUCCESS) {
        tloge("gp crypto finish: run fail, in len %u, out len %u\n", koi->in_data->length, koi->out_data->length);
        return ret;
    }
    return ret;
}

static TEE_Result gp_finish_by_mod(struct gp_key_opera_input *koi)
{
    size_t out_len = koi->out_data->length;
    TEE_Result ret = TEE_SUCCESS;
    switch (koi->mode) {
    case TEE_MODE_ENCRYPT:
    case TEE_MODE_DECRYPT:
        ret = gp_crypto_finish(koi);
        if (ret != TEE_SUCCESS)
            tloge("gp finish:crypto fail\n");
        break;
    case TEE_MODE_DIGEST:
        ret = TEE_DigestDoFinal(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length,
                                (void *)koi->out_data->buffer, &out_len);
        koi->out_data->length = out_len;
        break;
    case TEE_MODE_SIGN:
    case TEE_MODE_VERIFY:
        ret = gp_sign_verify_finish(koi);
        break;
    case TEE_MODE_MAC:
        ret = TEE_MACComputeFinal(koi->crypto_oper, koi->in_data->buffer, koi->in_data->length,
            koi->out_data->buffer, &out_len);
        koi->out_data->length = out_len;
        break;
    default:
        tloge("unsupport mod %u\n", koi->mode);
        ret = TEE_ERROR_BAD_STATE;
        break;
    }
    return ret;
}

TEE_Result gp_finish(const struct kms_buffer_data *opt_handle, uint32_t kms_mod,
    const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    bool check = (opt_handle == NULL || opt_handle->length != sizeof(uint64_t) || in_data == NULL ||
        out_data == NULL || out_data->buffer == NULL);
    if (check) {
        tloge("gp finish: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /*
     * concurency re-entry the same operation handle could crash, check and set a flag to prevent re-entry,
     * if set flag using, must free the keynode while exiting
     */
    TEE_Result ret = set_ophandle_state(*(uint64_t *)opt_handle->buffer, USING);
    if (ret != TEE_SUCCESS) {
        tloge("set ophandle state %u failed, ret = 0x%x\n", USING, ret);
        return ret;
    }
    TEE_Result free_ret;
    struct kms_key_node *key_node = NULL;
    ret = get_and_check_key_node(opt_handle, kms_mod, &key_node);
    if (ret != TEE_SUCCESS) {
        tloge("gp finish: key node is not valid, ret = 0x%x\n", ret);
        goto error;
    }
    struct gp_key_opera_input *koi = (struct gp_key_opera_input *)key_node->key_operate;
    koi->in_data = in_data;
    koi->out_data = out_data;
    ret = gp_finish_by_mod(koi);
    if (ret != TEE_SUCCESS)
        tloge("gp finish: finish do fail, ret = 0x%x\n", ret);
    free_koi_cache(koi);
error:
    free_ret = delete_free_key_node(*(uint64_t *)opt_handle->buffer);
    if (free_ret != TEE_SUCCESS) {
        /* this should never fail, otherwise this node memory could not be freeed */
        tloge("gp finish: delete key node fail, may memory leak, free_ret = 0x%x, ret = 0x%x\n", free_ret, ret);
        ret = (ret == TEE_SUCCESS) ? free_ret : ret;
    }
    return ret;
}

void gp_abort(const struct kms_buffer_data *opt_handle)
{
    if (opt_handle == NULL || opt_handle->buffer == NULL || opt_handle->length != sizeof(uint64_t)) {
        tloge("gp abort: input is invalid\n");
        return;
    }
    uint64_t handle = *(uint64_t *)opt_handle->buffer;
    /*
     * concurency re-entry the same operation handle could crash, check and set a flag to prevent re-entry,
     * if set flag using, must free the keynode while exiting
     */
    TEE_Result ret = set_ophandle_state(*(uint64_t *)opt_handle->buffer, USING);
    if (ret != TEE_SUCCESS) {
        tloge("set ophandle state %u failed, ret = 0x%x\n", USING, ret);
        return;
    }
    if (delete_free_key_node(handle) != TEE_SUCCESS)
        tloge("gp abort: delete key node fail, may memory leak\n");
    return;
}
