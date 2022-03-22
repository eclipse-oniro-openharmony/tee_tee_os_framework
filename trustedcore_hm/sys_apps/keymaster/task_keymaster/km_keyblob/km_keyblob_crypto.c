/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto process for keyblob itself
 * Create: 2020-12-01
 */

#include <sre_typedef.h>
#include "keymaster_defs.h"
#include "securec.h"
#include "tee_inner_uuid.h"
#include "km_types.h"
#include "keyblob.h"
#include "tee_private_api.h"
#include "km_env.h"
#include "km_crypto.h"
#include "km_key_check.h"
#include "km_common.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "tee_internal_huk_api.h"
#endif
/* This is a key derivor, not a key. */
uint8_t g_aes_key_secret[] = { 'T', 'r', 'u', 's', 't', 'e', 'd', 'C', 'o', 'r',
                               'e', 'k', 'e', 'y', 'm', 'a', 's', 't', 'e', 'r' };
TEE_Result decrypt_keyblob_hidden(keyblob_head *key_blob, const struct kb_crypto_factors *factors)
{
    TEE_Result ret;
    if (key_blob == NULL || factors == NULL) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_blob_internal_check(key_blob, key_blob->keyblob_total_size) != TEE_SUCCESS) {
        tloge("invalid keyblob\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t hidden_size = key_blob->extend2_buf_offset - key_blob->hidden_offset + key_blob->extend2_size;
    keymaster_blob_t encrypt_auth = { NULL, hidden_size };
    keymaster_blob_t decrypt_auth = { (uint8_t *)key_blob + key_blob->hidden_offset, hidden_size };
    struct keyblob_crypto_ctx ctx = {
        key_blob->version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        NO_EXTRA_ITERATE,
#endif
        { key_blob->hidden_iv, IV_LEN },
        *factors
    };
    encrypt_auth.data_addr = (uint8_t *)TEE_Malloc(hidden_size, TEE_MALLOC_FILL_ZERO);
    /* decrypt hidden param to verify APPLICATION_ID and APPLICATION_DATA */
    if (encrypt_auth.data_addr == NULL) {
        tloge("malloc failed, size %u\n", hidden_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(encrypt_auth.data_addr, hidden_size, decrypt_auth.data_addr, hidden_size) != EOK) {
        tloge("memcpy_s failed\n");
        erase_free_blob(&encrypt_auth);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = keyblob_crypto(&encrypt_auth, &decrypt_auth, &ctx);
    if (ret != TEE_SUCCESS)
        tloge("decrypt hidden failed, ret = %x\n", ret);
    erase_free_blob(&encrypt_auth);
    return ret;
}

int32_t encrypt_keyblob_hidden(keymaster_key_param_set_t *hidden, keyblob_head *keyblob,
    const struct kb_crypto_factors *factors)
{
    bool check_fail = (keyblob == NULL || factors == NULL);
    if (check_fail) {
        tloge("null pointer error!");
        return -1;
    }
    check_fail = (keyblob->extend2_size > KEY_BLOB_MAX_SIZE || KEY_BLOB_MAX_SIZE - keyblob->extend2_size <
        sizeof(uint32_t) || (KEY_BLOB_MAX_SIZE - keyblob->extend2_size - sizeof(uint32_t)) /
        sizeof(keymaster_key_param_t) < hidden->length);
    if (check_fail) {
        tloge("calc hidden size failed");
        return -1;
    }
    uint32_t hidden_size = hidden->length * sizeof(keymaster_key_param_t) + sizeof(uint32_t) + keyblob->extend2_size;
    TEE_GenerateRandom(keyblob->hidden_iv, IV_LEN);
    if (is_buff_zero(keyblob->hidden_iv, IV_LEN)) {
        tloge("keyblob hidden iv random failed\n");
        return -1;
    }
    keymaster_blob_t plain_hidden = { NULL, hidden_size };
    keymaster_blob_t cipher_hidden = { (uint8_t *)hidden, hidden_size };
    struct keyblob_crypto_ctx ctx = {
        keyblob->version, (uint32_t)TEE_MODE_ENCRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        NO_EXTRA_ITERATE,
#endif
        { keyblob->hidden_iv, IV_LEN },
        *factors
    };

    plain_hidden.data_addr = (uint8_t *)TEE_Malloc(hidden_size, TEE_MALLOC_FILL_ZERO);
    if (plain_hidden.data_addr == NULL) {
        tloge("malloc failed, hidden size is %u\n", hidden_size);
        return -1;
    }
    if (memcpy_s(plain_hidden.data_addr, hidden_size, (uint8_t *)hidden, hidden_size) != EOK) {
        tloge("memcpy hidden buff failed\n");
        erase_free_blob(&plain_hidden);
        return -1;
    }
    if (keyblob_crypto(&plain_hidden, &cipher_hidden, &ctx) != TEE_SUCCESS) {
        tloge("encrypt hidden_buf failed\n");
        erase_free_blob(&plain_hidden);
        return -1;
    }
    erase_free_blob(&plain_hidden);
    return 0;
}

#define AES_BLOCK_SIZE 16
static TEE_Result check_copy_data(const keymaster_blob_t *data_in, keymaster_blob_t *data_out, uint32_t crypto_size)
{
    bool check_fail = (data_in == NULL || data_out == NULL || data_in->data_addr == NULL ||
        data_out->data_addr == NULL);
    if (check_fail) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (data_in->data_length == crypto_size)
        return TEE_SUCCESS;
    errno_t rc = memmove_s(data_out->data_addr + crypto_size, data_out->data_length - crypto_size,
        data_in->data_addr + crypto_size, data_in->data_length % AES_BLOCK_SIZE);
    if (rc != EOK) {
        tloge("memmove_s failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result calc_secret_buff_len(const struct keyblob_crypto_ctx *ctx, uint32_t *total_len)
{
    bool condition = (total_len == NULL || ctx == NULL);
    if (condition) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *total_len = sizeof(g_aes_key_secret) + sizeof(TEE_UUID);
    tlogd("total_len1 %u", *total_len);
    keymaster_blob_t app_id = ctx->factors.app_id;
    condition = (app_id.data_addr != NULL && app_id.data_length != 0);
    if (condition) {
        if (UINT32_MAX - *total_len < app_id.data_length) {
            tloge("app id length is too large\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *total_len += app_id.data_length;
    }
    tlogd("total_len2 %u", *total_len);
    keymaster_blob_t inse_factor = ctx->factors.inse_factor;
    condition = (inse_factor.data_addr != NULL && inse_factor.data_length != 0);
    if (condition) {
        if (UINT32_MAX - *total_len < inse_factor.data_length) {
            tloge("inse_factor length is too large");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *total_len += inse_factor.data_length;
    }
    tlogd("total_len %u", *total_len);
    return TEE_SUCCESS;
}

static TEE_Result insert(keymaster_blob_t *sec_buf, uint32_t *offset, const keymaster_blob_t *item)
{
    bool condition = (sec_buf == NULL || sec_buf->data_addr == NULL || offset == NULL);
    if (condition) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (item == NULL || item->data_length == 0) {
        tlogd("item is null or length is zero, no need insert\n");
        return TEE_SUCCESS;
    }
    condition = (sec_buf->data_length < *offset || (sec_buf->data_length - *offset) < item->data_length);
    if (condition) {
        tloge("buffer too short, buff len %u, offset %u, datalen %u\n", sec_buf->data_length, *offset,
            item->data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (item->data_addr == NULL) {
        tloge("null input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((memmove_s(sec_buf->data_addr + *offset, sec_buf->data_length - *offset,
        (void *)item->data_addr, item->data_length) != EOK)) {
        tloge("memmove item to buffer failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (UINT32_MAX - item->data_length < *offset) {
        tloge("integer overflow\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *offset += item->data_length;
    return TEE_SUCCESS;
}

static TEE_Result build_kdf_buf(keymaster_blob_t *kdf_buf, const struct keyblob_crypto_ctx *ctx)
{
    bool check_fail = (kdf_buf == NULL || kdf_buf->data_addr == NULL);
    if (check_fail) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_UUID current_id = TEE_SERVICE_KEYMASTER;
    keymaster_blob_t key_secret = { g_aes_key_secret, sizeof(g_aes_key_secret) };
    keymaster_blob_t uid = { (uint8_t *)&current_id, sizeof(TEE_UUID) };
    uint32_t offset = 0;
#ifdef DUMP_MSG
    dump_msg("app_id\n", (ctx->factors.app_id).data_addr, (ctx->factors.app_id).data_length);
    dump_msg("inse_factor\n", (ctx->factors.inse_factor).data_addr, (ctx->factors.inse_factor).data_length);
#endif
    TEE_Result ret = insert(kdf_buf, &offset, &key_secret);
    if (ret != TEE_SUCCESS) {
        tloge("insert aes key salt failed\n");
        return ret;
    }
#ifdef DUMP_MSG
    dump_msg("kdf_buf1\n", kdf_buf->data_addr, kdf_buf->data_length);
#endif
    ret = insert(kdf_buf, &offset, &uid);
    if (ret != TEE_SUCCESS) {
        tloge("insert uid failed\n");
        return ret;
    }
#ifdef DUMP_MSG
    dump_msg("kdf_buf2\n", kdf_buf->data_addr, kdf_buf->data_length);
#endif
    ret = insert(kdf_buf, &offset, &(ctx->factors.app_id));
    if (ret != TEE_SUCCESS) {
        tloge("insert appid failed\n");
        return ret;
    }
    tlogd("insert appid success\n");
#ifdef DUMP_MSG
    dump_msg("kdf_buf3\n", kdf_buf->data_addr, kdf_buf->data_length);
#endif
    ret = insert(kdf_buf, &offset, &(ctx->factors.inse_factor));
    if (ret != TEE_SUCCESS) {
        tloge("insert inse_factor failed\n");
        return ret;
    }
    tlogd("insert inse_factor success\n");
#ifdef DUMP_MSG
    dump_msg("kdf_buf\n", kdf_buf->data_addr, kdf_buf->data_length);
#endif
    return TEE_SUCCESS;
}

static TEE_Result handle_version_without_appid(keymaster_blob_t *aes_key)
{
    bool check_fail = (aes_key == NULL || aes_key->data_addr == NULL || aes_key->data_length != AES_KEY_LEN);
    if (check_fail) {
        tloge("bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    errno_t rc;
    uint8_t secret_buff[sizeof(g_aes_key_secret) + sizeof(TEE_UUID)] = { 0 };
    TEE_UUID current_id                                              = TEE_SERVICE_KEYMASTER;

    rc = memmove_s(secret_buff, sizeof(secret_buff), g_aes_key_secret, sizeof(g_aes_key_secret));
    if (rc != EOK) {
        tloge("[error]memmove_s failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    rc = memmove_s((uint8_t *)secret_buff + sizeof(g_aes_key_secret), sizeof(TEE_UUID), (void *)&current_id,
                   sizeof(TEE_UUID));
    if (rc != EOK) {
        tloge("[error]memmove_s failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }

    /* derive key from root key */
    if (TEE_EXT_ROOT_DeriveKey2(secret_buff, sizeof(secret_buff), aes_key->data_addr, AES_KEY_LEN)) {
        tloge("derive key fromm root key failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result build_kdf_buf_with_ctx(const struct keyblob_crypto_ctx *ctx, keymaster_blob_t *kdf_buf)
{
    if (calc_secret_buff_len(ctx, &(kdf_buf->data_length)) != TEE_SUCCESS) {
        tloge("calc secret buff len failed\n");
        return TEE_ERROR_GENERIC;
    }
    tlogd("kdf buf data length %u", kdf_buf->data_length);
    kdf_buf->data_addr = TEE_Malloc(kdf_buf->data_length, TEE_MALLOC_FILL_ZERO);
    if (kdf_buf->data_addr == NULL) {
        tloge("buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    return build_kdf_buf(kdf_buf, ctx);
}

static TEE_Result handle_version_with_appid(const struct keyblob_crypto_ctx *ctx, keymaster_blob_t *aes_key)
{
    bool check_fail = (ctx == NULL || aes_key == NULL || aes_key->data_addr == NULL ||
        aes_key->data_length != AES_KEY_LEN);
    if (check_fail) {
        tloge("bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_blob_t kdf_buf = { NULL, 0 };
    TEE_Result ret = build_kdf_buf_with_ctx(ctx, &kdf_buf);
    if (ret != TEE_SUCCESS) {
        tloge("handle version with appid: build kdf salt buff failed");
        goto release;
    }
    tlogd("build kdf buf with appid success");
    /* derive key from root key */
    ret = TEE_EXT_ROOT_DeriveKey2(kdf_buf.data_addr, kdf_buf.data_length, aes_key->data_addr, aes_key->data_length);
    if (ret != TEE_SUCCESS)
        tloge("derive key fromm root key failed\n");
release:
    free_blob(&kdf_buf);
    return ret;
}

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#define HASH_512_LEN 64
static TEE_Result hash_salt(const uint8_t *buff, uint32_t buf_len, uint8_t *hash, uint32_t *hash_len)
{
    bool check_fail = (buff == NULL || hash == NULL || hash_len == NULL || *hash_len < HASH_512_LEN);
    if (check_fail) {
        tloge("invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_AllocateOperation(&operation, TEE_ALG_SHA512, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("digest:alloc operation fail");
        return ret;
    }
    TEE_DigestUpdate(operation, (void *)buff, (size_t)buf_len);
    size_t tmp_out_len = *hash_len;
    ret = TEE_DigestDoFinal(operation, NULL, (size_t)0, (void *)hash, &tmp_out_len);
    if (ret != TEE_SUCCESS) {
        tloge("digest do final failed");
        goto error;
    }
    if (tmp_out_len != HASH_512_LEN) {
        tloge("hash len wrong %zu", tmp_out_len);
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

static TEE_Result enhanced_kdf(const struct keyblob_crypto_ctx *ctx, const keymaster_blob_t *kdf_factor_buf,
    keymaster_blob_t *aes_key)
{
    bool check_fail = (ctx == NULL || kdf_factor_buf == NULL || aes_key == NULL || kdf_factor_buf->data_addr == NULL ||
        kdf_factor_buf->data_length == 0 || aes_key->data_addr == NULL || aes_key->data_length != AES_KEY_LEN);
    if (check_fail) {
        tloge("bad parameter");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t salt_hash[HASH_512_LEN] = { 0 };
    uint32_t hash_len = HASH_512_LEN;
    TEE_Result ret = hash_salt(kdf_factor_buf->data_addr, kdf_factor_buf->data_length, salt_hash, &hash_len);
    if (ret != TEE_SUCCESS) {
        tloge("salt hash failed, hash len %u", hash_len);
        return ret;
    }

    /* derive key from root key */
    ret = TEE_EXT_ROOT_DeriveKey2(salt_hash, hash_len, aes_key->data_addr, aes_key->data_length);
    if (ret != TEE_SUCCESS) {
        tloge("derive key fromm root key failed\n");
        return ret;
    }
    uint8_t temp_buff[AES_KEY_LEN] = { 0 };
    if (ctx->iterate_flag == EXTRA_ITERATE && KEYMASTER_ITRATION_TIMES > 0) {
        if (memmove_s(temp_buff, AES_KEY_LEN, aes_key->data_addr, aes_key->data_length) != EOK) {
            tloge("tmp key memmove_s failed\n");
            ret = TEE_ERROR_GENERIC;
            goto release;
        }
        tlogd("start: outter times:%u, inner times:%u", KEYMASTER_ITRATION_TIMES, DERIVE_ROOT_INTERNAL_ITRATIONS);
        /* derive key from root key */
        struct meminfo_t salt = { (uint64_t)(uintptr_t)temp_buff, AES_KEY_LEN };
        struct meminfo_t key = { (uint64_t)(uintptr_t)(aes_key->data_addr), aes_key->data_length };
        ret = tee_internal_derive_key2_iter(&salt, &key, KEYMASTER_ITRATION_TIMES, DERIVE_ROOT_INTERNAL_ITRATIONS);
        if (ret != TEE_SUCCESS) {
            tloge("derive key with iteration failed\n");
            goto release;
        }
        tlogd("ending interation");
    }
release:
    (void)memset_s(temp_buff, sizeof(temp_buff), 0, sizeof(temp_buff));
    return ret;
}

static TEE_Result handle_version_enhanced_pin(const struct keyblob_crypto_ctx *ctx, keymaster_blob_t *aes_key)
{
    bool check_fail = (ctx == NULL || aes_key == NULL || aes_key->data_addr == NULL ||
        aes_key->data_length != AES_KEY_LEN);
    if (check_fail) {
        tloge("bad parameter");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keymaster_blob_t kdf_buf = { NULL, 0 };
    TEE_Result ret = build_kdf_buf_with_ctx(ctx, &kdf_buf);
    if (ret != TEE_SUCCESS) {
        tloge("handle version enhanced pin: build kdf salt buff failed");
        goto release;
    }
    tlogd("build kdf buf with enhanced pin success");
    ret = enhanced_kdf(ctx, &kdf_buf, aes_key);
    if (ret != TEE_SUCCESS)
        tloge("enhanced pin derive key failed, ret 0x%x", ret);
release:
    free_blob(&kdf_buf);
    return ret;
}
#endif

static TEE_Result handle_versions(const struct keyblob_crypto_ctx *ctx, keymaster_blob_t *aes_key)
{
    TEE_Result ret = TEE_SUCCESS;
    bool check_fail = (ctx == NULL || aes_key == NULL || aes_key->data_addr == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool deprecated_version = ((ctx->keyblob_version == VERSION_100) || (ctx->keyblob_version == VERSION_110) ||
        (ctx->keyblob_version == VERSION_200) || (ctx->keyblob_version == VERSION_210));
    bool without_appid_version = ((ctx->keyblob_version == VERSION_220) || (ctx->keyblob_version == VERSION_230) ||
        (ctx->keyblob_version == VERSION_520) || (ctx->keyblob_version == VERSION_530));
    bool appid_version = ((ctx->keyblob_version == VERSION_300) || (ctx->keyblob_version == VERSION_310) ||
        (ctx->keyblob_version == VERSION_500) || (ctx->keyblob_version == VERSION_510));
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    bool enhanced_key_version = (ctx->keyblob_version == VERSION_340 || ctx->keyblob_version == VERSION_540 ||
        ctx->keyblob_version == VERSION_341 || ctx->keyblob_version == VERSION_541);
#endif
    if (deprecated_version) {
        /* deprecated_version(must use dx) cant't derive key */
        tloge("deprecated version derive key failed\n");
        return TEE_ERROR_GENERIC;
    } else if (without_appid_version) {
        ret = handle_version_without_appid(aes_key);
    } else if ((appid_version) && (ctx->factors.app_id).data_addr != NULL) {
        ret = handle_version_with_appid(ctx, aes_key);
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    } else if (enhanced_key_version) {
        ret = handle_version_enhanced_pin(ctx, aes_key);
#endif
    } else {
        tloge("invalid version %u\n", ctx->keyblob_version);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return ret;
}

static TEE_ObjectHandle aes_generate_key(uint8_t *aes_key, uint32_t key_size, uint32_t max_key_size)
{
    TEE_Result ret;
    TEE_Attribute attrib = { 0 };
    TEE_ObjectHandle gen_key = TEE_HANDLE_NULL;

    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, max_key_size, &gen_key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute allocate transient object:0x%x\n", ret);
        return NULL;
    }
    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, aes_key, key_size);
    ret = TEE_PopulateTransientObject(gen_key, &attrib, 1ul);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute populate transient object:0x%x\n", ret);
        TEE_FreeTransientObject(gen_key);
        gen_key = TEE_HANDLE_NULL;
        return NULL;
    }
    return gen_key;
}

#define MAX_AES_KEY_SIZE_KEYBLOB (AES_KEY_LEN * 8)
static TEE_Result aes_crypto_init(TEE_OperationHandle *aes_handle, keymaster_blob_t *aes_key,
    const keymaster_blob_t *iv, uint32_t mode, bool full_crypto_flag)
{
    bool check_fail = (aes_handle == NULL || aes_key == NULL || iv == NULL || aes_key->data_addr == NULL ||
        iv->data_addr == NULL || aes_key->data_length != AES_KEY_LEN || iv->data_length != IV_LEN);
    if (check_fail) {
        tloge("invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    uint32_t algorithm = ((full_crypto_flag) ? TEE_ALG_AES_CTR : TEE_ALG_AES_CBC_NOPAD);
    TEE_ObjectHandle key_object = aes_generate_key(aes_key->data_addr, aes_key->data_length, MAX_AES_KEY_SIZE_KEYBLOB);
    if (key_object == TEE_HANDLE_NULL) {
        tloge("Err input KEY\n");
        ret = TEE_ERROR_GENERIC;
        goto release;
    }
    ret = init_key_operation(aes_handle, algorithm, mode, MAX_AES_KEY_SIZE_KEYBLOB, &key_object);
    if (ret != TEE_SUCCESS) {
        tloge("allocate and init operation failed, ret 0x%x\n", ret);
        goto release;
    }
    TEE_CipherInit(*aes_handle, iv->data_addr, (size_t)IV_LEN);
release:
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    return ret;
}

static TEE_Result do_aes_crypto(TEE_OperationHandle aes_handle, bool full_crypto_flag, const keymaster_blob_t *data_in,
    keymaster_blob_t *data_out)
{
    TEE_Result ret;
    bool check_fail = (data_in == NULL || data_in->data_addr == NULL || data_out == NULL ||
        data_in->data_length != data_out->data_length);
    if (check_fail) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t crypto_size = ((full_crypto_flag) ? data_in->data_length :
        (data_in->data_length - (data_in->data_length % AES_BLOCK_SIZE)));
    size_t data_out_size = (size_t)data_out->data_length;
    ret = TEE_CipherDoFinal(aes_handle, data_in->data_addr, crypto_size, data_out->data_addr, &data_out_size);
    if (ret != TEE_SUCCESS) {
        tloge("Aes crypto failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (crypto_size != data_out_size) {
        tloge("unexpected error");
        return TEE_ERROR_GENERIC;
    }
    if (full_crypto_flag)
        return TEE_SUCCESS;

    return check_copy_data(data_in, data_out, crypto_size);
}
static TEE_Result check_keyblob_crypto_params(const keymaster_blob_t *data_in, keymaster_blob_t *data_out,
    const struct keyblob_crypto_ctx *ctx)
{
    bool condition_check = (data_in == NULL || data_out == NULL || ctx == NULL || ctx->iv.data_addr == NULL ||
        data_in->data_addr == NULL || data_out->data_addr == NULL);
    if (condition_check == true) {
        tloge("The input parameter is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    condition_check = (ctx->iv.data_length != IV_LEN || data_in->data_length != data_out->data_length);
    if (condition_check == true) {
        tloge("The input parameter is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result keyblob_crypto(const keymaster_blob_t *data_in, keymaster_blob_t *data_out,
    const struct keyblob_crypto_ctx *ctx)
{
    errno_t rc;
    uint8_t aes_key[AES_KEY_LEN] = { 0 };
    TEE_Result ret = check_keyblob_crypto_params(data_in, data_out, ctx);
    if (ret != TEE_SUCCESS)
        return ret;
    keymaster_blob_t kek = { aes_key, AES_KEY_LEN};
    ret = handle_versions(ctx, &kek);
    if (ret != TEE_SUCCESS) {
        tloge("Produce aes key failed");
        return ret;
    }

    TEE_OperationHandle aes_handle = TEE_HANDLE_NULL;
    bool full_crypto_flag = ((ctx->keyblob_version == VERSION_230) || (ctx->keyblob_version == VERSION_310) ||
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        (ctx->keyblob_version == VERSION_530) || (ctx->keyblob_version == VERSION_510) ||
        (ctx->keyblob_version == VERSION_340) || (ctx->keyblob_version == VERSION_540) ||
        (ctx->keyblob_version == VERSION_341) || (ctx->keyblob_version == VERSION_541));
#else
        (ctx->keyblob_version == VERSION_530) || (ctx->keyblob_version == VERSION_510));
#endif
    ret = aes_crypto_init(&aes_handle, &kek, &(ctx->iv), ctx->op_mode, full_crypto_flag);
    if (ret != TEE_SUCCESS) {
        tloge("Aes crypto init failed");
        goto end;
    }

    ret = do_aes_crypto(aes_handle, full_crypto_flag, data_in, data_out);
    if (ret != TEE_SUCCESS)
        tloge("Aes crypto failed");
end:
    rc = memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (rc != EOK) {
        tloge("[error]memset_s failed, rc=%d\n", rc);
        ret = TEE_ERROR_GENERIC;
    }
    TEE_FreeOperation(aes_handle);
    aes_handle = TEE_HANDLE_NULL;
    return ret;
}
