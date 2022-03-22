/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster import key process
 * Create: 2020-11-09
 */
#include "securec.h"
#include "km_types.h"
#include "km_tag_operation.h"
#include "keymaster_defs.h"
#include "km_common.h"
#include "km_crypto_adaptor.h"
#include "km_crypto_check.h"
#include "km_crypto.h"

static uint8_t *fill_first_zero_to_dest_len(uint8_t *input_buff, uint32_t input_buff_len, uint32_t out_buff_len)
{
    bool check_fail = (input_buff == NULL || input_buff_len > out_buff_len || out_buff_len > KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("null pointer or bad parameters\n");
        return NULL;
    }
    if (input_buff_len == out_buff_len) {
        tlogd("input buff len is the same as out buff len, success\n");
        return input_buff;
    } else {
        uint8_t *out_buff = TEE_Malloc(out_buff_len, TEE_MALLOC_FILL_ZERO);
        if (out_buff == NULL) {
            tloge("malloc failed\n");
            return NULL;
        }
        errno_t rc = memcpy_s(out_buff + (out_buff_len - input_buff_len), input_buff_len, input_buff,
            input_buff_len);
        if (rc != EOK) {
            tloge("memcpy_s failed\n");
            (void)memset_s(out_buff, out_buff_len, 0, out_buff_len);
            TEE_Free(out_buff);
            out_buff = NULL;
            return NULL;
        }
        tlogd("fill zero before data success\n");
        return out_buff;
    }
}

static void align_ec_key_buff_len_fail(const struct ec_key_header *header, uint8_t *x, uint8_t *y,
    uint8_t *priv_key, uint32_t key_size)
{
    bool check_need_free = (x != NULL && header->x_len < key_size);
    if (check_need_free) {
        TEE_Free(x);
        x = NULL;
    }
    check_need_free = (y != NULL && header->y_len < key_size);
    if (check_need_free) {
        TEE_Free(y);
        y = NULL;
    }
    check_need_free = (priv_key != NULL && header->priv_key_len < key_size);
    if (check_need_free) {
        (void)memset_s(priv_key, key_size, 0, key_size);
        TEE_Free(priv_key);
        priv_key = NULL;
    }
}

static TEE_Result align_ec_key_buff_len(uint8_t *param_buffer, struct ec_key_header *header,
    uint8_t **x, uint8_t **y, uint8_t **priv_key)
{
    bool check_fail = (param_buffer == NULL || header == NULL || x == NULL || y == NULL || priv_key == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t target_key_size_byte = eight_align_up(header->key_size) / BITS_ONE_BYTE;
    /* extract key value out */
    *x = fill_first_zero_to_dest_len(param_buffer + sizeof(*header), header->x_len, target_key_size_byte);
    if (*x == NULL) {
        tloge("get x value failed, x_len %u, target_size %u\n", header->x_len, target_key_size_byte);
        goto release;
    }
    *y = fill_first_zero_to_dest_len(param_buffer + sizeof(*header) + header->x_len, header->y_len,
        target_key_size_byte);
    if (*y == NULL) {
        tloge("get y value failed, y_len %u, target_size %u\n", header->y_len, target_key_size_byte);
        goto release;
    }
    *priv_key = fill_first_zero_to_dest_len(param_buffer + sizeof(*header) + header->x_len + header->y_len,
        header->priv_key_len, target_key_size_byte);
    if (*priv_key == NULL) {
        tloge("get priv key failed, priv_key_len %u, target_size %u\n", header->priv_key_len, target_key_size_byte);
        goto release;
    }
    return TEE_SUCCESS;
release:
    align_ec_key_buff_len_fail(header, *x, *y, *priv_key, target_key_size_byte);

    return TEE_ERROR_GENERIC;
}
static TEE_Result transfer_buffer_and_populate_obj(TEE_ObjectHandle key_obj, uint8_t *param_buffer,
    struct ec_key_header *header, TEE_ECC_CURVE ec_curve)
{
    bool check_fail = (param_buffer == NULL || header == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_GENERIC;
    }
    TEE_Result ret = TEE_ERROR_GENERIC;
    uint8_t *x = NULL;
    uint8_t *y = NULL;
    uint8_t *priv_key = NULL;
    uint32_t target_key_size_byte = eight_align_up(header->key_size) / BITS_ONE_BYTE;
    /* extract key value out */
    if (align_ec_key_buff_len(param_buffer, header, &x, &y, &priv_key) != TEE_SUCCESS) {
        tloge("prepare aligned key_buffer failed\n");
        goto release;
    }
    TEE_Attribute attr[EC_ATTR_CNT];
    TEE_InitValueAttribute(&attr[0], TEE_ATTR_ECC_CURVE, ec_curve, 0);
    TEE_InitRefAttribute(&attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_X, x, target_key_size_byte);
    TEE_InitRefAttribute(&attr[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y, y, target_key_size_byte);
    TEE_InitRefAttribute(&attr[3], TEE_ATTR_ECC_PRIVATE_VALUE, priv_key, target_key_size_byte);
    ret = TEE_PopulateTransientObject(key_obj, attr, EC_ATTR_CNT);
    if (ret != TEE_SUCCESS)
        tloge("set ec key: populate key failed: 0x%x\n", ret);
    else
        tlogd("set ec key: populate key obj success\n");
release:
    align_ec_key_buff_len_fail(header, x, y, priv_key, target_key_size_byte);
    return ret;
}
static TEE_Result populate_ec_key_obj(uint8_t *param_buffer, uint32_t param_size,
    TEE_ObjectHandle key_obj, const keymaster_key_param_set_t *params_hw_enforced, TEE_ECC_CURVE *gp_ec_curve)
{
    TEE_Result ret;
    struct ec_key_header *header = (struct ec_key_header *)param_buffer;
    uint32_t key_data_need_size = header->x_len + header->y_len + header->priv_key_len + sizeof(*header);
    if (param_size != key_data_need_size) {
        tloge("invalid buffer size, input size %u, expect %u\n", param_size, key_data_need_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_obj->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1(key_obj, key_obj->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return ret;
    }
    /* check if input keysize suited curve type is match with KM_TAG_EC_CURVE */
    ret = check_curve_value_with_type(gp_ec_curve, params_hw_enforced, header->key_size);
    if (ret != TEE_SUCCESS) {
        tloge("check_curve_value_with_type failed\n");
        return ret;
    }
    return transfer_buffer_and_populate_obj(key_obj, param_buffer, header, *gp_ec_curve);
}
TEE_Result import_ec_key(TEE_Param *params, const keymaster_key_param_set_t *params_hw_enforced, uint32_t version)
{
    keymaster_blob_t keymaterial = { NULL, 0 };
    if (params == NULL || params_hw_enforced == NULL || params[PARAM_ONE].memref.size < sizeof(struct ec_key_header)) {
        tloge("null pointer, or invalid key data buffer size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t key_size_in_param = 0;
    /* extract header out */
    struct ec_key_header *header = (struct ec_key_header *)params[PARAM_ONE].memref.buffer;
    /* check if the input key is matched with KM_TAG_KEY_SIZE */
    if ((get_key_param(KM_TAG_KEY_SIZE, &key_size_in_param, params_hw_enforced)) == 0 &&
        (key_size_in_param != header->key_size)) {
        tloge("KM_TAG_KEY_SIZE %u isn't same as key's size %u\n", key_size_in_param, header->key_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    TEE_Result ret = get_key_object(KM_ALGORITHM_EC, header->key_size, params_hw_enforced, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    TEE_ECC_CURVE gp_ec_curve;
    ret = populate_ec_key_obj((uint8_t *)params[PARAM_ONE].memref.buffer, params[PARAM_ONE].memref.size,
        key_obj, params_hw_enforced, &gp_ec_curve);
    if (ret != TEE_SUCCESS) {
        tloge("populate ec key object failed\n");
        goto release;
    }

    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        goto release;
    }
    ret = generate_ec_keymaterial(key_obj, gp_ec_curve, version, &factors, &keymaterial);
    if (ret != TEE_SUCCESS) {
        tloge("generate ec keymaterial failed:%x\n", ret);
        goto release;
    }
    ret = generate_unknown_keyblob(version, params, keymaterial.data_addr, keymaterial.data_length);
    if (ret != TEE_SUCCESS) {
        tloge("genrate ec keyblob failed\n");
        goto release;
    }
release:
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    free_blob(&keymaterial);
    return ret;
}

static TEE_Result key_object_init(TEE_ObjectHandle *key_obj, const keymaster_key_param_set_t *params_hw_enforced,
    keymaster_algorithm_t algorithm, uint32_t key_size_bytes)
{
    TEE_Result ret = get_key_object(algorithm, key_size_bytes * KM_BYTE_SIZE_8, params_hw_enforced, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }

    (*key_obj)->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1(*key_obj, (*key_obj)->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        TEE_FreeTransientObject(*key_obj);
        *key_obj = TEE_HANDLE_NULL;
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result import_sym_key_gen_keyblob(keymaster_algorithm_t algorithm, uint32_t key_size_bytes,
    TEE_Param *params, uint32_t version)
{
    keymaster_blob_t keymaterial = { NULL, 0 };
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    keymaster_key_param_set_t *params_hw_enforced = params[PARAM_ZERO].memref.buffer;

    TEE_Result ret = key_object_init(&key_obj, params_hw_enforced, algorithm, key_size_bytes);
    if (ret != TEE_SUCCESS) {
        tloge("key object init failed\n");
        return ret;
    }

    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        ret = TEE_ERROR_GENERIC;
        goto release;
    }

    /* Notice: we will check 3des weak key here when we support 3des algorithm in KM4.0 */
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, (uint8_t *)params[PARAM_ONE].memref.buffer, key_size_bytes);
    ret = TEE_PopulateTransientObject(key_obj, &attr, 1);
    if (ret != TEE_SUCCESS) {
        tloge("set symmetry key: populate key failed: 0x%x\n", ret);
        goto release;
    }

    ret = generate_symmetric_keymaterial(key_obj, &factors, version, &keymaterial);
    if (ret != TEE_SUCCESS) {
        tloge("generate symmetric keymaterial failed, ret is %x\n", ret);
        goto release;
    }

    ret = generate_unknown_keyblob(version, params, keymaterial.data_addr, keymaterial.data_length);
    if (ret != TEE_SUCCESS) {
        tloge("generate_keyblob failed\n");
        goto release;
    }

release:
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    free_blob(&keymaterial);
    return ret;
}

TEE_Result import_symmetric_key(TEE_Param *params, keymaster_algorithm_t algorithm,
                                const keymaster_key_param_set_t *params_hw_enforced, uint32_t version)
{
    uint32_t key_size_bytes = params[PARAM_ONE].memref.size;
    uint32_t key_size_in_param = 0;
    if (key_size_bytes > KEY_BLOB_MAX_SIZE) {
        tloge("key_size_bytes is invaild\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check_fail = ((algorithm == KM_ALGORITHM_AES) && ((key_size_bytes * KM_BYTE_SIZE_8) != KM_KEY_SIZE_128) &&
        ((key_size_bytes * KM_BYTE_SIZE_8) != KM_KEY_SIZE_192) &&
        ((key_size_bytes * KM_BYTE_SIZE_8) != KM_KEY_SIZE_256));
    if (check_fail) {
        tloge("CTS AES_SUPPORTED_KEY_SIZES = [128, 192, 256] in bits , this key_size = %u in bits\n",
            key_size_bytes * KM_BYTE_SIZE_8);
        return TEE_ERROR_GENERIC;
    }
    keymaster_error_t ret = check_aes_tag(algorithm, params_hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("import aes tag check error ret = 0x%x", ret);
        return (TEE_Result)ret;
    }
    check_fail = ((algorithm == KM_ALGORITHM_TRIPLE_DES) && ((key_size_bytes * KM_BYTE_SIZE_8) != KM_KEY_SIZE_192));
    if (check_fail) {
        tloge("CTS TRIPLE_DES_SUPPORTED_KEY_SIZES = [192] in bits , this key_size = %u in bits\n",
            key_size_bytes * KM_BYTE_SIZE_8);
        return TEE_ERROR_GENERIC;
    }
    check_fail = (algorithm == KM_ALGORITHM_HMAC && key_size_bytes > KM_KEY_SIZE_1536);
    if (check_fail) {
        /* VTS have test HMAC key_size with 131 bytes */
        tloge("hmac invalid keysize %u\n", key_size_bytes);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* check if the input key is matched with KM_TAG_KEY_SIZE */
    check_fail = ((get_key_param(KM_TAG_KEY_SIZE, &key_size_in_param, params_hw_enforced) == 0) &&
        (key_size_in_param != key_size_bytes * KM_BYTE_SIZE_8));
    if (check_fail) {
        tloge("KM_TAG_KEY_SIZE %u isn't same as key's size %u\n", key_size_in_param,
            key_size_bytes * KM_BYTE_SIZE_8);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (import_sym_key_gen_keyblob(algorithm, key_size_bytes, params, version) != TEE_SUCCESS) {
        tloge("import sym key and gen keyblob failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static int32_t rsa_key_size_check(uint32_t key_size_bytes)
{
    bool check_fail = (key_size_bytes == 0 || key_size_bytes > KM_KEY_SIZE_4096 / KM_BYTE_SIZE_8);
    if (check_fail) {
        tloge("key size in bytes %u is invalid\n", key_size_bytes);
        return -1;
    }
    return 0;
}

int32_t rsa_key_check_rsa_params(const struct rsa_key_header *rsa, uint32_t total_size)
{
    if (rsa_key_size_check(rsa->key_size_bytes) != 0) {
        tloge("invalid keysize\n");
        return -1;
    }
    if (rsa_key_size_check(rsa->pub_mod_len) != 0) {
        tloge("invalid pub_mod_len\n");
        return -1;
    }
    if (rsa->pub_exp_len > (total_size - sizeof(struct rsa_key_header))) {
        tloge("invalid pub_exp_len\n");
        return -1;
    }

    return 0;
}

static int32_t rsa_key_check_crt_mode(const struct rsa_key_header *rsa)
{
    uint32_t crt_mode = rsa->key_type;
    if (crt_mode == TEE_KEYPAIR_RSA) {
        if (rsa_key_size_check(rsa->rsa_priv.exp_len)) {
            tloge("invalid rsa_priv len\n");
            return -1;
        }
    } else if (crt_mode == TEE_KEYPAIR_RSACRT) {
        bool check_fail = ((rsa->crtrsa_priv.p_len > rsa->key_size_bytes) ||
            (rsa->crtrsa_priv.q_len > rsa->key_size_bytes) || (rsa->crtrsa_priv.dp_len > rsa->key_size_bytes) ||
            (rsa->crtrsa_priv.dq_len > rsa->key_size_bytes) || (rsa->crtrsa_priv.qinv_len > rsa->key_size_bytes));
        if (check_fail) {
            tloge("invalid crtrsa_priv len\n");
            return -1;
        }
    } else {
        tloge("invalid crt_mode %u\n", crt_mode);
        return -1;
    }

    return 0;
}

static int32_t rsa_key_check(const struct rsa_key_header *rsa, uint32_t total_size,
    const keymaster_key_param_set_t *params_hw_enforced)
{
    int32_t ret;
    bool check_fail = (rsa == NULL || params_hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointers\n");
        return -1;
    }
    ret = rsa_key_check_rsa_params(rsa, total_size);
    if (ret != 0)
        return ret;

    ret = rsa_key_check_crt_mode(rsa);
    if (ret != 0)
        return ret;

    uint32_t key_size_in_param = 0;
    check_fail = ((get_key_param(KM_TAG_KEY_SIZE, &key_size_in_param, params_hw_enforced) == 0) &&
        (key_size_in_param != (rsa->key_size_bytes * KM_BYTE_SIZE_8)));
    if (check_fail) {
        tloge("KM_TAG_KEY_SIZE %u isn't same as key's size %u\n", key_size_in_param,
            rsa->key_size_bytes * KM_BYTE_SIZE_8);
        return -1;
    }

    return 0;
}

static TEE_Result init_key_attribute_from_buffer(uint8_t *buffer, uint32_t buff_len,
    const struct rsa_key_header *header, TEE_Attribute *attr, uint32_t attr_cnt)
{
    bool invalid_params = ((header == NULL || buffer == NULL || attr == NULL) ||
        (header->key_type == TEE_KEYPAIR_RSA && attr_cnt != RSA_NOCRT_ATTR_CNT) ||
        (header->key_type == TEE_KEYPAIR_RSACRT && attr_cnt != RSA_CRT_ATTR_CNT));
    if (invalid_params) {
        tloge("null pointer or invalid attribute buffer len\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t offset = 0;
    /*
     * NOTICE: imported rsa key struct
     * RSA key data:
     * |--key metadata--|--public modulus--|--public exponent--|--private exponent--|
     *
     * RSA CRT key data:
     * |--key metadata--|--public modulus--|--public exponent--|--P--|--Q--|--DP--|--DQ--|--Qinv--|
     */
    uint32_t gp_attr_sequence[RSA_CRT_ATTR_CNT] = { TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT,
        TEE_ATTR_RSA_PRIVATE_EXPONENT, TEE_ATTR_RSA_PRIME1, TEE_ATTR_RSA_PRIME2, TEE_ATTR_RSA_EXPONENT1,
        TEE_ATTR_RSA_EXPONENT2, TEE_ATTR_RSA_COEFFICIENT };
    uint32_t element_length[RSA_CRT_ATTR_CNT] = { header->pub_mod_len, header->pub_exp_len,
        /* fill private_exponent with prime1 data, because priv_expoent is not used in crtmod */
        0, header->crtrsa_priv.p_len, header->crtrsa_priv.q_len, header->crtrsa_priv.dp_len,
        header->crtrsa_priv.dq_len, header->crtrsa_priv.qinv_len };
    uint32_t i = 0;
    for (; i < attr_cnt; i++) {
        if (i == RSA_CRT_ATTR_PRIV_EXP_INDEX) {
            if (header->key_type == TEE_KEYPAIR_RSA) {
                element_length[RSA_CRT_ATTR_PRIV_EXP_INDEX] = header->rsa_priv.exp_len;
                tlogd("no crt mode, priv e len %u\n", header->rsa_priv.exp_len);
            }
        }
        if (buff_len - offset < element_length[i]) {
            tloge("buff_len is small, index %u, offset %u, element_length %u\n", i, offset, element_length[i]);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        TEE_InitRefAttribute(&attr[i], gp_attr_sequence[i], buffer + offset, element_length[i]);
        /* input data does not contains private_exponent (d) data in crt mode, its element_length = 0 */
        offset += element_length[i];
    }
    return TEE_SUCCESS;
}


static TEE_Result check_pub_exponent(uint8_t *buffer, uint32_t buff_len, struct rsa_key_header *header,
    const keymaster_key_param_set_t *params_hw_enforced)
{
    bool invalid_params = (header == NULL || buffer == NULL || params_hw_enforced == NULL);
    if (invalid_params) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    invalid_params = (header->pub_mod_len > buff_len || UINT32_MAX - header->pub_mod_len < header->pub_exp_len ||
        header->pub_mod_len + header->pub_exp_len > buff_len);
    if (invalid_params) {
        tloge("invalid length\n");
        return TEE_ERROR_GENERIC;
    }
    uint8_t *pub_exponent_ptr = buffer + header->pub_mod_len;
    uint64_t public_exponent = 0;
    uint64_t temp = byte_to_int64(pub_exponent_ptr, header->pub_exp_len);
        /* check if the input key is matched with KM_TAG_RSA_PUBLIC_EXPONENT */
    if ((get_key_param(KM_TAG_RSA_PUBLIC_EXPONENT, &public_exponent, params_hw_enforced) == 0) &&
        (public_exponent != temp)) {
        tloge("KM_TAG_RSA_PUBLIC_EXPONENT isn't same as key's\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (temp < MIN_INSECURE_RSA_PUB_E)
        tlogw("Warning: An insecure rsa param e is being used: %I64x\n", temp);
    return TEE_SUCCESS;
}

static TEE_Result get_rsa_key_obj_by_key_type(TEE_ObjectHandle key_obj, struct rsa_key_header *header,
    uint32_t *attrb_len)
{
    if (header->key_type == TEE_KEYPAIR_RSA) {
        *attrb_len = RSA_NOCRT_ATTR_CNT;
        key_obj->CRTMode = GP_NOCRT_MODE; /* convert to GP crt mode value */
    } else if (header->key_type == TEE_KEYPAIR_RSACRT) {
        key_obj->CRTMode = GP_CRT_MODE; /* convert to GP crt mode value */
        *attrb_len = RSA_CRT_ATTR_CNT;
    } else {
        tloge("wrong rsa key_type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result populate_rsa_key_obj(TEE_ObjectHandle key_obj, struct rsa_key_header *header,
    uint8_t *param_buffer, uint32_t param_buf_size)
{
    TEE_Result ret;
    key_obj->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1(key_obj, key_obj->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return ret;
    }
    uint32_t attrb_len = 0;
    ret = get_rsa_key_obj_by_key_type(key_obj, header, &attrb_len);
    if (ret != TEE_SUCCESS)
        return ret;
    TEE_Attribute *attr = (TEE_Attribute *)TEE_Malloc(sizeof(TEE_Attribute) * attrb_len, TEE_MALLOC_FILL_ZERO);
    if (attr == NULL) {
        tloge("malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = init_key_attribute_from_buffer((uint8_t *)param_buffer + sizeof(*header), param_buf_size,
        header, attr, attrb_len);
    if (ret != TEE_SUCCESS)
        goto release;
    ret = TEE_PopulateTransientObject(key_obj, attr, attrb_len);
    if (ret != TEE_SUCCESS) {
        tloge("set rsa key: populate key failed: 0x%x\n", ret);
        goto release;
    }
    tlogd("key obj crtmode %u\n", key_obj->CRTMode);
release:
    TEE_Free(attr);
    attr = NULL;
    return ret;
}
TEE_Result import_rsa_key(TEE_Param *params, const keymaster_key_param_set_t *params_hw_enforced, uint32_t version)
{
    /* caller km_import_key has checked params, params_hw_enforced pointers */
    TEE_Result ret;
    keymaster_blob_t key_material = { NULL, 0 };
    /* get import key form NS */
    uint32_t param_buf_size = params[PARAM_ONE].memref.size;
    if (param_buf_size <= sizeof(struct rsa_key_header)) {
        tloge("rsa_key buf size invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct rsa_key_header *header = (struct rsa_key_header *)params[PARAM_ONE].memref.buffer;
    if (rsa_key_check(header, param_buf_size, params_hw_enforced) != 0) {
        tloge("rsa key info check failed\n");
        return TEE_ERROR_GENERIC;
    }
    /* check if the input key is matched with KM_TAG_KEY_SIZE */
    param_buf_size -= sizeof(struct rsa_key_header);
    ret = check_pub_exponent((uint8_t *)params[PARAM_ONE].memref.buffer + sizeof(*header), param_buf_size, header,
        params_hw_enforced);
    if (ret != TEE_SUCCESS)
        return ret;

    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    ret = get_key_object(KM_ALGORITHM_RSA, header->key_size_bytes * KM_BYTE_SIZE_8, params_hw_enforced, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    ret = populate_rsa_key_obj(key_obj, header, (uint8_t *)params[PARAM_ONE].memref.buffer, param_buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("rsa popultated key object failed, ret 0x%x\n", ret);
        goto release;
    }
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        goto release;
    }
    ret = generate_rsa_keymaterial(key_obj, version, &factors, &key_material);
    if (ret != TEE_SUCCESS) {
        tloge("rsa generate keymaterial failed, ret 0x%x\n", ret);
        goto release;
    }
    /* generate key_blob */
    ret = generate_unknown_keyblob(version, params, key_material.data_addr, key_material.data_length);
    if (ret != TEE_SUCCESS)
        tloge("generate unknown source keyblob failed\n");
release:
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    TEE_Free(key_material.data_addr);
    key_material.data_addr = NULL;
    return ret;
}
