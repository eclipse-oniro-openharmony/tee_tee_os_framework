/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster generate keyblob process
 * Create: 2020-11-09
 */
#include <sre_typedef.h>
#include "securec.h"
#include "keyblob.h"
#include "km_common.h"
#include "km_tag_operation.h"
#include "km_env.h"
#include "km_rollback_resistance.h"
#include "km_crypto_adaptor.h"
#include "km_key_params.h"
#include "km_auth.h"
#include "km_crypto.h"

static int origin_convert(keymaster_key_origin_t *acture_origin, uint8_t key_origin_ext)
{
    if (acture_origin == NULL)
        return -1;
    keymaster_uint2uint key_origin_mapping_list[] = {
        { KM_KEY_GENERATED, KM_ORIGIN_GENERATED}, { KM_KEY_IMPORTED, KM_ORIGIN_IMPORTED},
        { KM_KEY_SECURELY_IMPORTED, KM_ORIGIN_SECURELY_IMPORTED}
    };
    if (look_up_table(key_origin_mapping_list, sizeof(key_origin_mapping_list) / sizeof(keymaster_uint2uint),
        key_origin_ext, acture_origin) != TEE_SUCCESS) {
        tloge("key_origin_ext %u invalid\n", key_origin_ext);
        return -1;
    }
    return 0;
}

static TEE_Result generate_symmetric_key(TEE_ObjectHandle object_handle, uint32_t key_size, uint32_t version,
                                         const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params)
{
    TEE_Result ret;
    keymaster_blob_t key_material = { NULL, 0 };
    tlogd("generate symmetric key begin\n");
    ret = TEE_GenerateKey(object_handle, key_size, NULL, 0);
    if (ret != TEE_SUCCESS) {
        tloge("generate key failed\n");
        return ret;
    }
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    /* NOTICE: for 3des key supporting, we will add weak keys check here */
    ret = generate_symmetric_keymaterial(object_handle, &factors, version, &key_material);
    if (ret != TEE_SUCCESS) {
        tloge("generate symmetric keymaterial failed, ret is 0x%x\n", ret);
        goto error;
    }

    ret = (TEE_Result)generate_keyblob(key_material.data_addr, key_material.data_length, KM_ORIGIN_GENERATED, params,
        version);
    TEE_Free(key_material.data_addr);
    key_material.data_addr = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("generate keyblob failed, tee_ret is 0x%x\n", ret);
        goto error;
    }
    tlogd("generate_symmetric_key success\n");
error:
    free_blob(&key_material);
    return ret;
}

static TEE_Result get_rsa_pub_exp_size_in_bytes(uint64_t public_exponent, uint32_t *pub_exp_size_in_bytes)
{
    bool check_range_in_bytes_2 = (public_exponent > 0xff) && (public_exponent <= 0xffff);
    bool check_range_in_bytes_3 = (public_exponent > 0xffff) && (public_exponent <= 0xffffff);
    bool check_range_in_bytes_4 = (public_exponent > 0xffffff) && (public_exponent <= 0xffffffff);
    if (public_exponent <= 0xff) {
        *pub_exp_size_in_bytes = KM_NUM_BYTES_1;
    } else if (check_range_in_bytes_2) {
        *pub_exp_size_in_bytes = KM_NUM_BYTES_2;
    } else if (check_range_in_bytes_3) {
        *pub_exp_size_in_bytes = KM_NUM_BYTES_3;
    } else if (check_range_in_bytes_4) {
        *pub_exp_size_in_bytes = KM_NUM_BYTES_4;
    } else {
        tloge("the parameters are error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result init_rsa_pub_e_attr(TEE_Attribute *attrb_params, const keymaster_key_param_set_t *params_hw_enforced)
{
    bool check_fail = (attrb_params == NULL || params_hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint64_t public_exponent = 0;
    keymaster_blob_t pub_exp = { (uint8_t *)&public_exponent, 0 };
    int32_t result = get_key_param(KM_TAG_RSA_PUBLIC_EXPONENT, &public_exponent, params_hw_enforced);
    /*
     * If no exponent is specified or if the specified exponent is not supported, key
     * generation must fail with KM_ERROR_INVALID_ARGUMENT. google file v1 p 18. add in 2019-8-6
     */
    if (result != 0) {
        tloge("No public exponent specified for RSA key generation");
        return (TEE_Result)KM_ERROR_INVALID_ARGUMENT;
    }
    if (public_exponent < MIN_INSECURE_RSA_PUB_E)
        tlogw("Warning: An insecure rsa param e is being used: %I64x\n", public_exponent);
    uint32_t length = 0;
    TEE_Result ret = get_rsa_pub_exp_size_in_bytes(public_exponent, &length);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exp size in bytes is failed\n");
        return ret;
    }
    pub_exp.data_length = length;
    if (memset_s(attrb_params, sizeof(*attrb_params), 0, sizeof(*attrb_params)) != EOK) {
        tloge("memset_s failed\n");
        return TEE_ERROR_GENERIC;
    }
    TEE_InitRefAttribute(attrb_params, TEE_ATTR_RSA_PUBLIC_EXPONENT, pub_exp.data_addr, pub_exp.data_length);
    return TEE_SUCCESS;
}

static TEE_Result generate_rsa_key(TEE_ObjectHandle object_handle, uint32_t key_size, uint32_t version,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params)
{
    tlogd("generate RSA keypair begin\n");
    TEE_Result ret;
    TEE_Attribute attrb_params;
    ret = init_rsa_pub_e_attr(&attrb_params, params_hw_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("init rsa pub e attribute failed\n");
        return ret;
    }
    object_handle->CRTMode = GP_CRT_MODE; /* default use crt mode */
    ret = TEE_GenerateKey(object_handle, key_size, &attrb_params, 1);
    if (ret != TEE_SUCCESS) {
        tloge("generate rsa key failed\n");
        return ret;
    }

    keymaster_blob_t keymaterial = { NULL, 0 };
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    ret = generate_rsa_keymaterial(object_handle, version, &factors, &keymaterial);
    if (ret != TEE_SUCCESS) {
        tloge("rsa generate keymaterial failed, ret 0x%x\n", ret);
        goto error;
    }
    /* generate key_blob */
    if (generate_keyblob(keymaterial.data_addr, keymaterial.data_length, KM_ORIGIN_GENERATED, params, version) != 0) {
        tloge("generate_keyblob failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    tlogd("generate_keyblob success\n");
    ret = TEE_SUCCESS;
error:
    free_blob(&keymaterial);
    return ret;
}

TEE_Result check_curve_value_with_type(TEE_ECC_CURVE *ecc_curv, const keymaster_key_param_set_t *params_hw_enforced,
    uint32_t key_size)
{
    keymaster_ec_curve_t ec_curve_tag_value = 0;

    /* get domain id of dx */
    int32_t ret = ec_keysize2nist_curve(key_size, ecc_curv);
    if (ret != 0)
        return TEE_ERROR_GENERIC;

    tlogd("ecc_curv = %d\n", *ecc_curv);
    /* check if input keysize suited curve type is match with KM_TAG_EC_CURVE */
    int iret = get_key_param(KM_TAG_EC_CURVE, &ec_curve_tag_value, params_hw_enforced);
    if ((iret == 0) && (ec_curve_tag_value != ec_nist_curve2kmcurve(*ecc_curv))) {
        tloge("KM_TAG_EC_CURVE %u isn't matched with curve type %d\n", ec_curve_tag_value, *ecc_curv);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result generate_ec_key(TEE_ObjectHandle object_handle, uint32_t key_size, uint32_t version,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params)
{
    TEE_Result ret;
    TEE_Attribute attrb_params;
    TEE_ECC_CURVE gp_ec_curve = 0;
    tlogd("generte ec key entry\n");
    /* check if input keysize suited curve type is match with KM_TAG_EC_CURVE */
    ret = check_curve_value_with_type(&gp_ec_curve, params_hw_enforced, key_size);
    if (ret != TEE_SUCCESS) {
        tloge("check_curve_value_with_type failed\n");
        return ret;
    }

    if (memset_s(&attrb_params, sizeof(attrb_params), 0, sizeof(attrb_params)) != EOK) {
        tloge("memset_s failed\n");
        return TEE_ERROR_GENERIC;
    }
    TEE_InitValueAttribute(&attrb_params, TEE_ATTR_ECC_CURVE, (uint32_t)gp_ec_curve, 0);
    ret = TEE_GenerateKey(object_handle, key_size, &attrb_params, 1);
    if (ret != TEE_SUCCESS) {
        tloge("generate ec key failed\n");
        return ret;
    }

    keymaster_blob_t keymaterial = { NULL, 0 };
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced, version, NULL, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    ret = generate_ec_keymaterial(object_handle, (uint32_t)gp_ec_curve, version, &factors, &keymaterial);
    if (ret != TEE_SUCCESS) {
        tloge("ecc generate keymaterial failed, ret 0x%x\n", ret);
        goto error;
    }

    /* generate key_blob */
    if (generate_keyblob(keymaterial.data_addr, keymaterial.data_length, KM_ORIGIN_GENERATED, params, version) != 0) {
        tloge("generate keyblob failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    tlogd("generate keyblob success\n");
    ret = TEE_SUCCESS;
error:
    free_blob(&keymaterial);
    return ret;
}


static TEE_Result generate_key_by_algorithm(keymaster_algorithm_t algorithm, uint32_t key_size,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params, TEE_ObjectHandle key_obj)
{
    uint32_t version;
    TEE_Result ret = get_cur_version(params_hw_enforced, algorithm, &version);
    if (ret != TEE_SUCCESS) {
        tloge("get version failed");
        return ret;
    }

    if (algorithm == KM_ALGORITHM_RSA) {
        ret = generate_rsa_key(key_obj, key_size, version, params_hw_enforced, params);
    } else if (algorithm == KM_ALGORITHM_EC) {
        ret = generate_ec_key(key_obj, key_size, version, params_hw_enforced, params);
    } else if (algorithm == KM_ALGORITHM_HMAC || algorithm == KM_ALGORITHM_AES ||
        algorithm == KM_ALGORITHM_TRIPLE_DES) {
        ret = generate_symmetric_key(key_obj, key_size, version, params_hw_enforced, params);
    } else {
        tloge("unsupported algorithm %d\n", algorithm);
        ret = TEE_ERROR_GENERIC;
    }
    if (ret != TEE_SUCCESS)
        tloge("generate key failed, algorithm = %d\n", algorithm);

    return ret;
}

TEE_Result generate_key(keymaster_algorithm_t algorithm, uint32_t key_size,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params)
{
    TEE_Result ret;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    ret = get_key_object(algorithm, key_size, params_hw_enforced, &key_obj); /* key_obj should be freed at the end */
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    key_obj->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1(key_obj, key_obj->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        TEE_FreeTransientObject(key_obj);
        return ret;
    }
    ret = generate_key_by_algorithm(algorithm, key_size, params_hw_enforced, params, key_obj);
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    return ret;
}

TEE_Result generate_unknown_keyblob(uint32_t version, TEE_Param *params, const uint8_t *keymaterial,
    uint32_t temp_size)
{
    /*
     * use param[PARAM_THREE] to get the actually key origin
     * 0: generated by openSSL
     * 1: actually import by keymaster HAL
     * 2: securely imported
     */
    uint8_t key_origin_ext = *(uint8_t *)params[PARAM_THREE].memref.buffer;
    keymaster_key_origin_t acture_origin = KM_ORIGIN_UNKNOWN;
    int ret = origin_convert(&acture_origin, key_origin_ext);
    if (ret != 0) {
        tloge("key_origin_ext 0x%x invalid\n", key_origin_ext);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* generate key_blob */
    ret = generate_keyblob(keymaterial, temp_size, acture_origin, params, version);
    if (ret != 0) {
        tloge("generate_keyblob failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t insert_data(keyblob_head *keyblob, uint32_t max_buff_len, const uint8_t *data, uint32_t data_len)
{
    if (keyblob == NULL || data == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (keyblob->keyblob_total_size > max_buff_len) {
        tloge("wrong keyblob size\n");
        return -1;
    }
    uint8_t *p = (uint8_t *)keyblob;
    errno_t rc = memcpy_s(p + keyblob->keyblob_total_size, max_buff_len - keyblob->keyblob_total_size, data, data_len);
    if (rc != EOK) {
        tloge("insert data to keyblob failed\n");
        return -1;
    }
    keyblob->keyblob_total_size += data_len;
    return 0;
}

static keymaster_error_t check_keyblob_buffer_basic(keymaster_blob_t *input_keyblob)
{
    bool check_fail = (input_keyblob == NULL || input_keyblob->data_addr == NULL);
    if (check_fail)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    if (input_keyblob->data_length < sizeof(keyblob_head))
        return KM_ERROR_INVALID_INPUT_LENGTH;
    return KM_ERROR_OK;
}
static int32_t insert_keymaterial(keymaster_blob_t *keyblob, const keymaster_blob_t *keymaterial)
{
    bool check_fail = (keyblob == NULL || keymaterial == NULL);
    if (check_fail) {
        tloge("null pointer");
        return -1;
    }
    if (check_keyblob_buffer_basic(keyblob) != KM_ERROR_OK) {
        tloge("wrong keyblob buffer\n");
        return -1;
    }
    keyblob_head *p = (keyblob_head *)(keyblob->data_addr);
    p->keymaterial_offset = p->keyblob_total_size;
    /* After the p value assigning statement, the data structure is |keyblob_head|keymaterial|  */
    if (insert_data(p, keyblob->data_length, keymaterial->data_addr, keymaterial->data_length) != 0) {
        tloge("insert_keymaterial faild\n");
        return -1;
    }
    p->keymaterial_size = keymaterial->data_length;
    return 0;
}

static int32_t insert_param(uint8_t *keyblob_data, uint32_t max_buff_len, const keymaster_key_param_t *param,
    uint32_t type)
{
    bool check_fail = (keyblob_data == NULL || param == NULL || max_buff_len < sizeof(keyblob_head));
    if (check_fail) {
        tloge("null pointer or wrong keyblob buffsize\n");\
        return -1;
    }

    keyblob_head *keyblob = (keyblob_head *)keyblob_data;
    check_fail = (keyblob->keyblob_total_size > max_buff_len || max_buff_len - keyblob->keyblob_total_size <
        sizeof(keymaster_key_param_t));
    if (check_fail) {
        tloge("wrong keyblob buffer size\n");
        return -1;
    }
    keymaster_key_param_set_t *enforced_param_set;
    if (type == 0) {
        enforced_param_set = (keymaster_key_param_set_t *)(keyblob_data + keyblob->hw_enforced_offset);
    } else if (type == 1) {
        enforced_param_set = (keymaster_key_param_set_t *)(keyblob_data + keyblob->sw_enforced_offset);
    } else {
        tloge("wront paramset type %u\n", type);
        return -1;
    }
    uint8_t *current_addr = (uint8_t *)enforced_param_set + enforced_param_set->length * sizeof(keymaster_key_param_t) +
        sizeof(uint32_t);
    errno_t rc = memcpy_s(current_addr, max_buff_len - keyblob->keyblob_total_size, param, sizeof(*param));
    if (rc != EOK) {
        tloge("copy param failed\n");
        return -1;
    }
    enforced_param_set->length++;
    keyblob->keyblob_total_size += sizeof(keymaster_key_param_t);
    return 0;
}

static int32_t get_first_param(const keymaster_key_param_set_t *param_set, keymaster_key_param_t **param)
{
    bool check_fail = (param_set == NULL || param == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    if (param_set->length > 0) {
        *param = (keymaster_key_param_t *)((uint8_t *)param_set + sizeof(uint32_t));
    } else {
        *param = NULL;
        return -1;
    }
    return 0;
}

static int32_t set_rsa_key_size_param(TEE_Param param_one, keymaster_key_param_t *to_set_param)
{
    bool check_fail = (param_one.memref.buffer == NULL || to_set_param == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    if (param_one.memref.size < sizeof(struct rsa_key_header)) {
        tloge("params[1] buffer size is too small\n");
        return -1;
    }
    struct rsa_key_header *header = (struct rsa_key_header *)param_one.memref.buffer;
    to_set_param->integer = header->key_size_bytes * KM_BYTE_SIZE_8;

    tlogd("set rsa KM_TAG_KEY_SIZE tag, keysize = %u in bits\n", to_set_param->integer);
    return 0;
}

static int32_t set_symmetric_key_size_param(TEE_Param param_one, keymaster_key_param_t *to_set_param)
{
    bool check_fail = (param_one.memref.buffer == NULL || to_set_param == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    /* keymaterial->keysize is in bytes, CTS want it as bits */
    uint32_t key_size_bytes = param_one.memref.size;
    if (key_size_bytes > KM_KEY_SIZE_4096) {
        tloge("set symmetirc key param, the key size is too large\n");
        return -1;
    }
    to_set_param->integer = key_size_bytes * KM_BYTE_SIZE_8;
    tlogd("set symmetric key KM_TAG_KEY_SIZE tag, keysize = %u in bits\n", to_set_param->integer);
    return 0;
}

static int32_t set_ec_key_size_param(TEE_Param param_one, keymaster_key_param_t *to_set_param)
{
    bool check_fail = (param_one.memref.buffer == NULL || to_set_param == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    if (param_one.memref.size < sizeof(struct ec_key_header)) {
        tloge("params[1] buffer size is too small\n");
        return -1;
    }
    /* keysize is in bytes, CTS want it as bits. */
    /* extract header out */
    struct ec_key_header *header = (struct ec_key_header *)param_one.memref.buffer;
    to_set_param->integer = header->key_size;
    tlogd("set EC KM_TAG_KEY_SIZE tag, keysize = %u in bits\n", to_set_param->integer);
    return 0;
}
static int32_t set_param_keysize(uint32_t enumerated, keymaster_key_param_t *add_param, const TEE_Param *params)
{
    int32_t ret;
    bool symmetric_algorithm = ((enumerated == KM_ALGORITHM_AES) || (enumerated == KM_ALGORITHM_TRIPLE_DES) ||
        (enumerated == KM_ALGORITHM_HMAC));

    /* for CTS testKeyStore_ImportSupportedSizes_AES/RSA/HMAC/EC */
    if (enumerated == KM_ALGORITHM_RSA) {
        ret = set_rsa_key_size_param(params[PARAM_ONE], add_param);
        if (ret != 0) {
            tloge("set rsa key size param failed, ret 0x%x\n", ret);
            return -1;
        }
    } else if (symmetric_algorithm) {
        ret = set_symmetric_key_size_param(params[PARAM_ONE], add_param);
        if (ret != 0) {
            tloge("set symmetric key size failed, ret 0x%x\n", ret);
            return -1;
        }
    } else if (enumerated == KM_ALGORITHM_EC) {
        ret = set_ec_key_size_param(params[PARAM_ONE], add_param);
        if (ret != 0) {
            tloge("set ec key_tag failed, ret 0x%x\n", ret);
            return -1;
        }
    } else {
        tloge("unsupport KM_TAG_ALGORITHM 0x%x\n", enumerated);
        return -1;
    }

    return 0;
}
static int32_t set_key_size_value(const keymaster_key_param_set_t *params_hw_enforced, keymaster_key_origin_t origin,
    keymaster_key_param_t *add_param, const TEE_Param *params, keymaster_blob_t *input_keyblob)
{
    uint32_t i;
    int32_t ret;
    bool alogrithm_tag_found = false;
    /*
     * Only when user import a key(that we can deside the key size) but didn't input a
     * KM_TAG_KEY_SIZE in params, we add the KM_TAG_KEY_SIZE in keyblob.
     */
    uint32_t key_size = 0;
    bool add_key_size = (origin == KM_ORIGIN_IMPORTED || origin == KM_ORIGIN_SECURELY_IMPORTED) &&
        get_key_param(KM_TAG_KEY_SIZE, &key_size, params_hw_enforced) != 0;
    if (!add_key_size) {
        tlogd("key size tag existed, success, key_size %u\n", key_size);
        return 0;
    }
    add_param->tag = KM_TAG_KEY_SIZE;
    keymaster_key_param_t *params_hw = NULL;
    if (get_first_param(params_hw_enforced, &params_hw) != 0) {
        tloge("get the first param in param set failed\n");
        return -1;
    }
    for (i = 0; i < params_hw_enforced->length; i++)
        if (params_hw[i].tag == KM_TAG_ALGORITHM) {
            alogrithm_tag_found = true;
            tlogd("params_hw[i].enumerated is 0x%x\n", params_hw[i].enumerated);
            ret = set_param_keysize(params_hw[i].enumerated, add_param, params);
            if (ret != 0) {
                tloge("set_param_keysize failed, ret 0x%x\n", ret);
                return ret;
            }
            break;
        }

    if (!alogrithm_tag_found) {
        tloge("get keymaster algorithm tag failed\n");
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;
    }
    /* insert KM_TAG_KEY_SIZE */
    ret = insert_param(input_keyblob->data_addr, input_keyblob->data_length, add_param, 0);
    if (ret != 0) {
        tloge("insert key size tag failed\n");
        return ret;
    }
    return 0;
}

static int32_t add_ec_curve_tag(const keymaster_key_param_set_t *params_hw_enforced,
    const keymaster_blob_t *keymaterial_blob, keymaster_key_param_t *add_param, keymaster_blob_t *input_keyblob)
{
    uint32_t ec_curve_value = 0;
    bool add_curve_tag;
    keymaster_algorithm_t algo;
    if (get_key_param(KM_TAG_ALGORITHM, &algo, params_hw_enforced) != 0) {
        tloge("get algorithm failed\n");
        return -1;
    }
    /* add for cts test of ec: KM_TAG_EC_CURVE tag add */
    add_curve_tag =
        (algo == KM_ALGORITHM_EC && get_key_param(KM_TAG_EC_CURVE, &ec_curve_value, params_hw_enforced) != 0);
    if (!add_curve_tag)
        return 0;

    const struct keymaterial_ecdsa_header *keymaterial_ec =
        (const struct keymaterial_ecdsa_header *)(keymaterial_blob->data_addr);
    add_param->tag = KM_TAG_EC_CURVE;
    add_param->integer = ec_nist_curve2kmcurve(keymaterial_ec->ecc_curv);
    if (add_param->integer == KM_EC_CURVE_P_OFF) {
        tloge("ec curve is off\n");
        return -1;
    }

    if (insert_param(input_keyblob->data_addr, input_keyblob->data_length, add_param, 0) != 0) {
        tloge("insert EC Curve tag failed\n");
        return -1;
    }
    tlogd("Add KM_EC_CURVE tag=%u\n", add_param->integer);
    return 0;
}

static void get_hidden_len(keymaster_blob_t application_id, keymaster_blob_t application_data, uint32_t *hidden_len)
{
    bool application_id_add = (application_id.data_addr != NULL && application_id.data_length != 0);
    if (application_id_add)
        (*hidden_len)++;

    bool application_data_add = (application_data.data_addr != NULL && application_data.data_length != 0);
    if (application_data_add)
        (*hidden_len)++;
    return;
}

static int set_application_tag_info(const keymaster_key_param_set_t *params_sw_enforced, const uint8_t *params_data,
    keymaster_blob_t *input_keyblob, keymaster_blob_t *application_id, keymaster_blob_t *application_data)
{
    errno_t rc;
    uint32_t i;
    keymaster_key_param_t *params_sw = (keymaster_key_param_t *)((uint8_t *)params_sw_enforced + sizeof(uint32_t));
    keyblob_head *keyblob = (keyblob_head *)(input_keyblob->data_addr);
    keymaster_key_param_set_t *sw_enforced = (keymaster_key_param_set_t *)(input_keyblob->data_addr +
        keyblob->sw_enforced_offset);
    uint32_t *keyblob_size = &(keyblob->keyblob_total_size);
    uint8_t *extend1_buf = input_keyblob->data_addr + keyblob->extend1_buf_offset;
    free_blob(application_id);
    free_blob(application_data);
    for (i = 0; i < params_sw_enforced->length; i++) {
        if (keymaster_tag_get_type(params_sw[i].tag) != KM_BIGNUM &&
            keymaster_tag_get_type(params_sw[i].tag) != KM_BYTES)
            continue;
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        if (params_sw[i].tag == KM_TAG_HW_ENHANCED_KEY_APPID)
            continue;
#endif
        if (params_sw[i].tag == KM_TAG_APPLICATION_ID) {
            /* If KM_TAG_APPLICATION_ID Tag is found, then set application_id data. */
            application_id->data_length = params_sw[i].blob.data_length;
            application_id->data_addr = (uint8_t *)params_data + (uint32_t)params_sw[i].blob.data_offset;
        } else if (params_sw[i].tag == KM_TAG_APPLICATION_DATA) {
            application_data->data_length = params_sw[i].blob.data_length;
            application_data->data_addr = (uint8_t *)params_data + (uint32_t)params_sw[i].blob.data_offset;
        } else {
            uint8_t *dst  = extend1_buf + keyblob->extend1_size;
            uint8_t *src  = (uint8_t *)params_data + (uint32_t)params_sw[i].blob.data_offset;
            uint32_t size = params_sw[i].blob.data_length;
            rc = memcpy_s(dst, KEY_BLOB_MAX_SIZE - *keyblob_size - keyblob->extend1_size, src, size);
            if (rc != EOK) {
                tloge("memset_s failed, rc 0x%x\n", rc);
                return -1;
            }
            /* we get offset of extend1_buf */
            keymaster_key_param_t *kb_param = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));
            kb_param[i].blob.data_offset = keyblob->extend1_size;
            keyblob->extend1_size += size;
        }
    }
    keyblob->extend1_buf_offset = *keyblob_size;
    *keyblob_size += keyblob->extend1_size;

    return 0;
}

static int32_t copy_application_to_hidden(const keymaster_blob_t *application_id,
    const keymaster_blob_t *application_data, keymaster_key_param_t *hidden_params, keymaster_key_param_set_t *hidden,
    keyblob_head *keyblob, uint8_t **extend2_buf)
{
    errno_t rc;

    if ((application_id->data_addr != NULL) && (application_id->data_length != 0)) {
        hidden_params[hidden->length].tag = KM_TAG_APPLICATION_ID;
        hidden_params[hidden->length].blob.data_length = application_id->data_length;
        hidden_params[hidden->length].blob.data_offset = keyblob->extend2_size;
        rc = memcpy_s(*extend2_buf, KEY_BLOB_MAX_SIZE - keyblob->extend2_buf_offset - keyblob->extend2_size,
                      application_id->data_addr, application_id->data_length);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0X%x\n", rc);
            return -1;
        }

        keyblob->extend2_size += application_id->data_length;
        *extend2_buf += application_id->data_length;
        hidden->length++;
    }

    if ((application_data->data_addr != NULL) && (application_data->data_length != 0)) {
        hidden_params[hidden->length].tag = KM_TAG_APPLICATION_DATA;
        hidden_params[hidden->length].blob.data_length = application_data->data_length;
        hidden_params[hidden->length].blob.data_offset = keyblob->extend2_size;
        rc = memcpy_s(*extend2_buf, KEY_BLOB_MAX_SIZE - keyblob->extend2_buf_offset - keyblob->extend2_size,
                      application_data->data_addr, application_data->data_length);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0X%x\n", rc);
            return -1;
        }

        keyblob->extend2_size += application_data->data_length;
        *extend2_buf += application_data->data_length;
        hidden->length++;
    }

    return 0;
}

static int32_t insert_rot(keymaster_blob_t *input_keyblob, uint8_t **extend2_buf)
{
    keyblob_head *keyblob = (keyblob_head *)(input_keyblob->data_addr);
    keymaster_key_param_set_t *hidden = (keymaster_key_param_set_t *)(input_keyblob->data_addr +
        keyblob->keyblob_total_size);
    keymaster_key_param_t *hidden_params = (keymaster_key_param_t *)(input_keyblob->data_addr +
        keyblob->keyblob_total_size + sizeof(uint32_t));
    hidden->length = 0;
    hidden_params[hidden->length].tag = KM_TAG_ROOT_OF_TRUST;
    hidden_params[hidden->length].blob.data_length = ROT_SIZE;
    hidden_params[hidden->length].blob.data_offset = keyblob->extend2_size;
    uint8_t *rot_buffer = get_rot();
    if (rot_buffer == NULL) {
        tloge("get_rot is null\n");
        return -1;
    }
    if (memcpy_s(*extend2_buf, KEY_BLOB_MAX_SIZE - keyblob->extend2_buf_offset - keyblob->extend2_size, rot_buffer,
        ROT_SIZE) != EOK) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    keyblob->extend2_size += ROT_SIZE;
    *extend2_buf += ROT_SIZE;
    hidden->length++;

    return 0;
}
static int32_t generate_hidden_data(keymaster_blob_t *application_id, const keymaster_blob_t *application_data,
    keymaster_blob_t *input_keyblob, const struct kb_crypto_factors *factors)
{
    uint32_t hidden_len = 1;
    int32_t ret;
    keyblob_head *keyblob = (keyblob_head *)(input_keyblob->data_addr);
    /* generate hidden */
    keyblob->hidden_offset = keyblob->keyblob_total_size;
    get_hidden_len(*application_id, *application_data, &hidden_len);
    if ((sizeof(keymaster_key_param_t) * hidden_len + sizeof(uint32_t)) >
        (input_keyblob->data_length - keyblob->keyblob_total_size)) {
        tloge("keyblob_size %u is error\n", keyblob->keyblob_total_size);
        return -1;
    }
    keyblob->extend2_buf_offset = keyblob->keyblob_total_size + hidden_len * sizeof(keymaster_key_param_t) +
        sizeof(uint32_t);
    keyblob->extend2_size = 0;
    keymaster_key_param_set_t *hidden = (keymaster_key_param_set_t *)(input_keyblob->data_addr +
        keyblob->keyblob_total_size);
    keymaster_key_param_t *hidden_params = (keymaster_key_param_t *)(input_keyblob->data_addr +
        keyblob->keyblob_total_size + sizeof(uint32_t));
    uint8_t *extend2_buf = input_keyblob->data_addr + keyblob->extend2_buf_offset;
    if (insert_rot(input_keyblob, &extend2_buf) != 0) {
        tloge("insert rot failed\n");
        return -1;
    }

    ret = copy_application_to_hidden(application_id, application_data, hidden_params, hidden, keyblob, &extend2_buf);
    if (ret != 0) {
        tloge("copy_application_to_hidden failed, ret 0x%x\n", ret);
        return ret;
    }

    keyblob->keyblob_total_size += hidden->length * sizeof(keymaster_key_param_t) + sizeof(uint32_t) +
        keyblob->extend2_size;
    tlogd("keyblob_size is %u\n", keyblob->keyblob_total_size);

    /* encrypt hidden */
    ret = encrypt_keyblob_hidden(hidden, keyblob, factors);
    if (ret != 0) {
        tloge("encrypt keyblob hidden failed, ret 0x%x\n", ret);
        return -1;
    }

    return 0;
}
static int32_t insert_key_usage_and_os_tags(const keymaster_key_param_set_t *params_hw_enforced, uint8_t *keyblob,
                                            uint32_t max_buff_len)
{
    keymaster_key_param_t hw_enforced_params;
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    /* set KM_TAG_ROLLBACK_RESISTANT If KM_PURPOSE_ROLLBACK_RESISTANT supports, then add KM_TAG_ROLLBACK_RESISTANT. */
    keymaster_purpose_t keyblob_purpose = KM_PURPOSE_ROLLBACK_RESISTANT;
    if (is_key_param_suport(KM_TAG_PURPOSE, (void *)&keyblob_purpose, params_hw_enforced) != 0) {
        hw_enforced_params.tag = KM_TAG_ROLLBACK_RESISTANT;
        hw_enforced_params.boolean = true;
        if (insert_param(keyblob, max_buff_len, &hw_enforced_params, 0) != 0) {
            tloge("insert rollback resistant tag failed\n");
            return -1;
        }
        tlogd("Purpose of rollback-resistance detected, Params added\n");
    }
#else
    (void)params_hw_enforced;
#endif
    /* set KM_TAG_OS_VERSION and KM_TAG_OS_PATCHLEVEL */
    hw_enforced_params.tag = KM_TAG_OS_VERSION;
    hw_enforced_params.integer = get_verify_boot_os_version();
    if (insert_param(keyblob, max_buff_len, &hw_enforced_params, 0) != 0) {
        tloge("insert os version tag failed\n");
        return -1;
    }
    tlogd("insert os version %u success\n", hw_enforced_params.integer);
    hw_enforced_params.tag = KM_TAG_OS_PATCHLEVEL;
    hw_enforced_params.integer = get_verify_boot_patch_level();
    if (insert_param(keyblob, max_buff_len, &hw_enforced_params, 0) != 0) {
        tloge("insert os patch level tag failed\n");
        return -1;
    }
    tlogd("insert os patch level %u success\n", hw_enforced_params.integer);
    /* set KM_TAG_BLOB_USAGE_REQUIREMENTS */
    hw_enforced_params.tag = KM_TAG_BLOB_USAGE_REQUIREMENTS;
    hw_enforced_params.enumerated = KM_BLOB_REQUIRES_FILE_SYSTEM;
    if (insert_param(keyblob, max_buff_len, &hw_enforced_params, 0) != 0) {
        tloge("insert blob usage requirements tag failed\n");
        return -1;
    }
    tlogd("insert blob usage requirements tag success, usage requirements %u\n", KM_BLOB_REQUIRES_FILE_SYSTEM);
    return 0;
}
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static int32_t insert_param_set_with_enhanced_key(keyblob_head *keyblob, uint32_t max_buff_len,
    const keymaster_key_param_set_t *param_set)
{
    uint32_t delete_offset = 0;
    for (uint32_t i = 0; i < param_set->length; i++) {
        keymaster_key_param_t *tmp_param = (keymaster_key_param_t *)((uint8_t *)param_set + sizeof(param_set->length));
        if (tmp_param[i].tag == KM_TAG_HW_ENHANCED_KEY_APPID) {
            delete_offset += tmp_param[i].blob.data_length; /* enhanced app id data should not be saved */
            tlogd("enhanced key appid tag should not be saved, length %u, skip offset %u\n",
                tmp_param[i].blob.data_length, delete_offset);
            continue;
        }
        if (insert_param((uint8_t *)keyblob, max_buff_len, &tmp_param[i], 0) != 0) {
            tloge("insert key tag origin tag failed\n");
            return -1;
        }
        if (keymaster_tag_get_type(tmp_param[i].tag) == KM_BIGNUM ||
            keymaster_tag_get_type(tmp_param[i].tag) == KM_BYTES) {
            keymaster_key_param_t *hw_param = (keymaster_key_param_t *)((uint8_t *)keyblob + keyblob->keyblob_total_size
                - sizeof(tmp_param[i]));
            if (hw_param[0].blob.data_offset < delete_offset) {
                tloge("blob data offset %u less than %u", tmp_param[i].blob.data_offset, delete_offset);
                return -1;
            }
            /* shift offset for all blob type param behind enhanced app id data */
            hw_param[0].blob.data_offset -= delete_offset;
        }
        tlogd("insert index %u, keyblob size %u", i, keyblob->keyblob_total_size);
    }

    return 0;
}
#endif
static int32_t insert_param_set(keyblob_head *keyblob, uint32_t max_buff_len,
    const keymaster_key_param_set_t *param_set)
{
    bool check_fail = (keyblob == NULL || param_set == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    if (keyblob->keyblob_total_size > max_buff_len) {
        tloge("wrong keyblob size\n");
        return -1;
    }
    uint32_t empty_size = max_buff_len - keyblob->keyblob_total_size;
    check_fail = (empty_size / sizeof(keymaster_key_param_t) < param_set->length ||
        empty_size - param_set->length * sizeof(keymaster_key_param_t) < sizeof(uint32_t));
    if (check_fail) {
        tloge("param set length calc overflow\n");
        return -1;
    }
    uint32_t *length = (uint32_t *)((uint8_t *)keyblob + keyblob->keyblob_total_size);
    keyblob->hw_enforced_offset = keyblob->keyblob_total_size;
    keyblob->keyblob_total_size += sizeof(*length);
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    *length = 0;
    if (insert_param_set_with_enhanced_key(keyblob, max_buff_len, param_set) != 0) {
        tloge("insert param set with enhanced_key failed\n");
        return -1;
    }
#else
    /* input hwenforced params doesn't contain bytes type or big num type data, we can copy the whole buffer */
    errno_t rc = memcpy_s((uint8_t *)keyblob + keyblob->keyblob_total_size, max_buff_len - keyblob->keyblob_total_size,
        (uint8_t *)param_set + sizeof(uint32_t), param_set->length * sizeof(keymaster_key_param_t));
    if (rc != EOK) {
        tloge("copy enforced_params failed\n");
        return -1;
    }
    *length = param_set->length;
    keyblob->keyblob_total_size += param_set->length * sizeof(keymaster_key_param_t);
#endif
    tlogd("paramset offset %u, copy param length %u, size %u,  finished keyblob_data_size %u\n",
        keyblob->hw_enforced_offset, param_set->length,
        param_set->length * sizeof(keymaster_key_param_t), keyblob->keyblob_total_size);
    return 0;
}

static int32_t build_hw_enforced_datas(keymaster_key_origin_t origin,
    const keymaster_key_param_set_t *params_hw_enforced, keymaster_blob_t *input_keyblob,
    const TEE_Param *params, const keymaster_blob_t *keymaterial_blob)
{
    int32_t ret;
    keymaster_key_param_t add_param;
    /* p->data structure :|keyblob_head|keymaterial|hw_enforced */
    ret = insert_param_set((keyblob_head *)(input_keyblob->data_addr), input_keyblob->data_length, params_hw_enforced);
    if (ret != 0) {
        tloge("insert hw param set failed\n");
        return ret;
    }
    ret = set_key_size_value(params_hw_enforced, origin, &add_param, params, input_keyblob);
    if (ret != 0) {
        tloge("set key size value is failed\n");
        return ret;
    }

    /* add for cts test of ec: KM_TAG_EC_CURVE tag add */
    ret = add_ec_curve_tag(params_hw_enforced, keymaterial_blob, &add_param, input_keyblob);
    if (ret != 0) {
        tloge("add_ec_curve_tag is failed\n");
        return ret;
    }

    add_param.tag = KM_TAG_ORIGIN;
    add_param.enumerated = (uint32_t)origin;
    ret = insert_param(input_keyblob->data_addr, input_keyblob->data_length, &add_param, 0);
    if (ret != 0) {
        tloge("insert key tag origin tag failed\n");
        return ret;
    }
    ret = insert_key_usage_and_os_tags(params_hw_enforced, input_keyblob->data_addr, input_keyblob->data_length);
    if (ret != 0) {
        tloge("insert key usage and os tags failed\n");
        return ret;
    }
    return 0;
}

static int32_t ouput_param3_data(TEE_Param *params, uint32_t keyblob_size, const keyblob_head *keyblob,
                                 const uint8_t *hw_enforced)
{
    if (params[PARAM_THREE].memref.buffer != NULL && params[PARAM_THREE].memref.size != 0) {
        if (keyblob_size - keyblob->hw_enforced_offset > params[PARAM_THREE].memref.size) {
            tloge("invalid params buffer size\n");
            return -1;
        }
        int32_t ret = resort_key_characteristics(params[PARAM_THREE].memref.buffer, (uint8_t *)hw_enforced,
            keyblob_size - keyblob->hw_enforced_offset);
        if (ret != 0) {
            tloge("resort_key_characteristics failed\n");
            return -1;
        }
        params[PARAM_THREE].memref.size = keyblob_size - keyblob->hw_enforced_offset;
    }

    return 0;
}

static int32_t ouput_param2_data(TEE_Param *params, uint32_t keyblob_size, const uint8_t *tmp)
{
    errno_t rc;

    if (keyblob_size > params[PARAM_TWO].memref.size) {
        tloge("invalid params buffer size\n");
        return -1;
    }
    rc = memcpy_s((uint8_t *)params[PARAM_TWO].memref.buffer, keyblob_size, tmp, keyblob_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0X%x\n", rc);
        return -1;
    }

    params[PARAM_TWO].memref.size = keyblob_size;

    return 0;
}

static int32_t process_out_params_and_hidden_data(TEE_Param *params, keymaster_blob_t *input_keyblob,
    keymaster_blob_t *application_id, const keymaster_blob_t *application_data, const struct kb_crypto_factors *factors)
{
    int32_t ret;
    keyblob_head *keyblob = (keyblob_head *)(input_keyblob->data_addr);
    uint8_t *hw_enforced = input_keyblob->data_addr + keyblob->hw_enforced_offset;
    /* output of params[PARAM_THREE]:keymaster_key_param_set_t hw_enforced sw_enforced */
    ret = ouput_param3_data(params, keyblob->keyblob_total_size, keyblob, hw_enforced);
    if (ret != 0) {
        tloge("ouput_param3_data is failed, ret=0x%x\n", ret);
        return -1;
    }

    /* generate hidden */
    ret = generate_hidden_data(application_id, application_data, input_keyblob, factors);
    if (ret != 0) {
        tloge("generate_hidden_data is failed\n");
        return -1;
    }

    /* calculate HMAC */
    if (keymaster_hmac(input_keyblob->data_addr + HMAC_SIZE, keyblob->keyblob_total_size - HMAC_SIZE, keyblob->hmac,
        GENERATE_HMAC, NULL, keyblob->version, application_id)) {
        tloge("keyblob_HMAC failed\n");
        return -1;
    }

    ret = ouput_param2_data(params, keyblob->keyblob_total_size, input_keyblob->data_addr);
    if (ret != 0) {
        tloge("ouput_param2_data is failed, ret=0x%x\n", ret);
        return -1;
    }
    return 0;
}

static int32_t init_param_sets(keymaster_key_param_set_t **params_hw_enforced,
    keymaster_key_param_set_t **params_sw_enforced, uint8_t **params_data, TEE_Param param)
{
    bool condition_check = (params_hw_enforced == NULL || params_sw_enforced == NULL ||
        params_data == NULL || param.memref.buffer == NULL);
    if (condition_check) {
        tloge("null pointer\n");
        return -1;
    }
    uint32_t offset = 0;
    bool invalid = false;
    if (param.memref.size < sizeof(keymaster_key_param_set_t) * KM_FACTOR_2) {
        tloge("param.memref.size is too small\n");
        return -1;
    }
    /* (keymaster_key_param_set_t *)param.memref.buffer has been check valid for hw_enforce and sw_enforce */
    keymaster_key_param_set_t *local_params_hw_enforced = (keymaster_key_param_set_t *)param.memref.buffer;
    uint32_t size = param.memref.size;
    tlogd("local_params_hw_enforced->length is %u\n", local_params_hw_enforced->length);
    invalid = (size / sizeof(keymaster_key_param_t) < local_params_hw_enforced->length ||
        size - sizeof(uint32_t) < sizeof(keymaster_key_param_t) * local_params_hw_enforced->length);
    if (invalid) {
        tloge("calc offset overflow\n");
        return -1;
    }
    offset += (sizeof(keymaster_key_param_t) * local_params_hw_enforced->length + sizeof(uint32_t));
    keymaster_key_param_set_t *local_params_sw_enforced =
        (keymaster_key_param_set_t *)((uint8_t *)local_params_hw_enforced + offset);
    if (local_params_sw_enforced == NULL) {
        tloge("local_params_sw_enforced is null\n");
        return -1;
    }
    tlogd("local_params_sw_enforced->length is %u\n", local_params_sw_enforced->length);
    size -= (sizeof(keymaster_key_param_t) * local_params_hw_enforced->length + sizeof(uint32_t));
    invalid = (size / sizeof(keymaster_key_param_t) < local_params_sw_enforced->length ||
        size - sizeof(uint32_t) < sizeof(keymaster_key_param_t) * local_params_sw_enforced->length);
    if (invalid) {
        tloge("calc sw offset overflow\n");
        return -1;
    }
    offset += (sizeof(keymaster_key_param_t) * local_params_sw_enforced->length + sizeof(uint32_t));
    if (check_km_params(local_params_hw_enforced, local_params_sw_enforced) != 0) {
        tloge("check km params failed\n");
        return -1;
    }
    uint8_t *local_params_data = (uint8_t *)local_params_hw_enforced + offset;

    *params_hw_enforced = local_params_hw_enforced;
    *params_sw_enforced = local_params_sw_enforced;
    *params_data = local_params_data;
    return 0;
}
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static int generate_tag_with_enhanced_key(uint32_t length, const keymaster_key_param_t *params_sw,
    keymaster_key_param_t *sw_enforced_params, keymaster_key_param_set_t *sw_enforced, uint32_t *keyblob_size)
{
    bool skipped_tag = false;
    uint32_t delete_offset = 0;
    for (uint32_t i = 0; i < length; i++) {
        skipped_tag = (params_sw[i].tag == KM_TAG_APPLICATION_ID || params_sw[i].tag == KM_TAG_APPLICATION_DATA ||
            params_sw[i].tag == KM_TAG_HW_ENHANCED_KEY_APPID);
        if (skipped_tag) {
            delete_offset += params_sw[i].blob.data_length;
            tlogd("tag %u should not be saved in sw params, length %u, skip offset %u\n",
                params_sw[i].tag, params_sw[i].blob.data_length, delete_offset);
            continue;
        }
        errno_t rc = memcpy_s(&(sw_enforced_params[sw_enforced->length]), KEY_BLOB_MAX_SIZE - *keyblob_size,
            &(params_sw[i]), sizeof(keymaster_key_param_t));
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0X%x\n", rc);
            return -1;
        }
        if (keymaster_tag_get_type(sw_enforced_params[sw_enforced->length].tag) == KM_BIGNUM ||
            keymaster_tag_get_type(sw_enforced_params[sw_enforced->length].tag) == KM_BYTES) {
            if (sw_enforced_params[sw_enforced->length].blob.data_offset < delete_offset) {
                tloge("blob after skipped blob data offset %u less than skipped offset %u",
                    sw_enforced_params[sw_enforced->length].blob.data_offset, delete_offset);
                return -1;
            }
            sw_enforced_params[sw_enforced->length].blob.data_offset -= delete_offset;
            tlogd("modify the saved data offset as %u, skipped %u",
                sw_enforced_params[sw_enforced->length].blob.data_offset, delete_offset);
        }
        sw_enforced->length++;
        *keyblob_size += sizeof(keymaster_key_param_t);
    }

    return 0;
}
#endif
static int get_time_value(UINT64 *time_value)
{
    if (time_value == NULL) {
        tloge("time value is null");
        return -1;
    }

    TEE_Time time;
    TEE_GetREETime(&time);
    *time_value = time.seconds;
    if (((UINT64_MAX - time.millis) / KM_MS_PER_SEC) < *time_value) {
        tloge("invalid time value %llX\n", *time_value);
        return -1;
    }
    *time_value = *time_value * KM_MS_PER_SEC + time.millis;

    return 0;
}

static int generate_creation_data_time_tag(const keymaster_key_param_set_t *params_sw_enforced, keyblob_head *keyblob,
                                           uint32_t *keyblob_size)
{
    keymaster_key_param_set_t *sw_enforced = (keymaster_key_param_set_t *)((uint8_t *)keyblob +
        keyblob->keyblob_total_size);
    keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));

    if (*keyblob_size + sizeof(uint32_t) > KEY_BLOB_MAX_SIZE) {
        tloge("keyblob_size %u is error\n", *keyblob_size);
        return -1;
    }
    keyblob->sw_enforced_offset = *keyblob_size;
    *keyblob_size += sizeof(uint32_t);
    sw_enforced->length = 0;
    keymaster_key_param_t *params_sw = (keymaster_key_param_t *)((uint8_t *)params_sw_enforced + sizeof(uint32_t));
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (generate_tag_with_enhanced_key(params_sw_enforced->length, params_sw, sw_enforced_params, sw_enforced,
        keyblob_size) != 0) {
        tloge("generate tag with enhanced_key failed\n");
        return -1;
    }
#else
    for (uint32_t i = 0; i < params_sw_enforced->length; i++) {
        if (params_sw[i].tag != KM_TAG_APPLICATION_ID && params_sw[i].tag != KM_TAG_APPLICATION_DATA) {
            errno_t rc = memcpy_s(&(sw_enforced_params[sw_enforced->length]), KEY_BLOB_MAX_SIZE - *keyblob_size,
                &(params_sw[i]), sizeof(keymaster_key_param_t));
            if (rc != EOK) {
                tloge("memcpy_s failed, rc 0X%x\n", rc);
                return -1;
            }
            sw_enforced->length++;
            *keyblob_size += sizeof(keymaster_key_param_t);
        }
    }
#endif
    /* add by keymasterTA, include KM_TAG_CREATION_DATETIME, KM_TAG_OS_VERSION, KM_TAG_OS_PATCHLEVEL */
    if ((KEY_BLOB_MAX_SIZE - *keyblob_size) < sizeof(keymaster_key_param_t)) {
        tloge("keyblob_size %u is error\n", *keyblob_size);
        return -1;
    }
    /* set KM_TAG_CREATION_DATETIME */
    sw_enforced_params[sw_enforced->length].tag = KM_TAG_CREATION_DATETIME;
    UINT64 time_value;
    if (get_time_value(&time_value) != 0) {
        tloge("get time value failed");
        return -1;
    }
    sw_enforced_params[sw_enforced->length].date_time = time_value;
    sw_enforced->length++;
    *keyblob_size += sizeof(keymaster_key_param_t);
    return 0;
}

static int copy_extend_buffer(const keymaster_key_param_set_t *params_hw_enforced,
                              const uint8_t *params_data, uint8_t *extend1_buf, uint32_t *extend1_buf_size,
                              const uint32_t *keyblob_size)
{
    /* copy extend buffer */
    uint32_t i;
    errno_t rc;
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)params_hw_enforced + sizeof(uint32_t));
    for (i = 0; i < params_hw_enforced->length; i++) {
        if (keymaster_tag_get_type(params_hw[i].tag) != KM_BIGNUM &&
            keymaster_tag_get_type(params_hw[i].tag) != KM_BYTES) {
            tlogd("not blob type data or tag %u should not save here\n", params_hw[i].tag);
            continue;
        }
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        if (params_hw[i].tag == KM_TAG_HW_ENHANCED_KEY_APPID) {
            tlogd("not blob type data or tag %u should not save here\n", params_hw[i].tag);
            continue;
        }
#endif
        uint8_t *dst  = extend1_buf + *extend1_buf_size;
        const uint8_t *src  = params_data + params_hw[i].blob.data_offset;
        uint32_t size = params_hw[i].blob.data_length;
        rc = memcpy_s(dst, KEY_BLOB_MAX_SIZE - *keyblob_size - *extend1_buf_size, src, size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0X%x\n", rc);
            return -1;
        }
        /* we get offset of extend1_buf */
        *extend1_buf_size += size;
    }
    return 0;
}

static int32_t fill_enforced_data(keymaster_blob_t *input_keyblob, const keymaster_key_param_set_t *params_hw_enforced,
    const keymaster_key_param_set_t *params_sw_enforced, const uint8_t *params_data, TEE_Param *params)
{
    keymaster_blob_t application_id = { NULL, 0 };
    keymaster_blob_t application_data = { NULL, 0 };
    bool check_null = (input_keyblob == NULL || input_keyblob->data_addr == NULL || params_hw_enforced == NULL ||
    params_sw_enforced == NULL || params_data == NULL || params == NULL);
    if (check_null) {
        tloge("null pointer\n");
        return -1;
    }
    /* start set sw_enforced params!!!!!  set creation data time */
    int32_t ret = generate_creation_data_time_tag(params_sw_enforced, (keyblob_head *)(input_keyblob->data_addr),
        &(((keyblob_head *)(input_keyblob->data_addr))->keyblob_total_size));
    if (ret != 0) {
        tloge("generate_creation_data_time_tag is failed, ret=0x%x\n", ret);
        return -1;
    }
    ((keyblob_head *)(input_keyblob->data_addr))->extend1_buf_offset =
        ((keyblob_head *)(input_keyblob->data_addr))->keyblob_total_size;
    ret = copy_extend_buffer(params_hw_enforced, params_data,
        input_keyblob->data_addr + ((keyblob_head *)(input_keyblob->data_addr))->extend1_buf_offset,
        &(((keyblob_head *)(input_keyblob->data_addr))->extend1_size),
        &(((keyblob_head *)(input_keyblob->data_addr))->keyblob_total_size));
    if (ret != 0) {
        tloge("copy_extend_buffer failed, ret 0x%x\n", ret);
        return -1;
    }
    /* client's application_id and application_data will store in hidden params, not here */
    ret = set_application_tag_info(params_sw_enforced, params_data, input_keyblob, &application_id, &application_data);
    if (ret != 0) {
        tloge("set_application_tag_info failed, ret 0x%x\n", ret);
        return -1;
    }
    /* now: p struct |keyblob_head|keymaterial|hw_enforced param set |sw_enforced_param set|extend_buff1| */
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors(params_hw_enforced, params_hw_enforced,
        ((keyblob_head *)(input_keyblob->data_addr))->version, &application_id, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return -1;
    }
    ret = process_out_params_and_hidden_data(params, input_keyblob, &application_id, &application_data, &factors);
    if (ret != 0) {
        tloge("process_out_params_and_hidden_data is failed, ret=0x%x\n", ret);
        return -1;
    }
    return 0;
}

static int32_t build_rpmb_keyblob_data(const keymaster_blob_t *input_keyblob,
    const keymaster_key_param_set_t *params_hw_enforced)
{
    keymaster_purpose_t keyblob_purpose = KM_PURPOSE_ROLLBACK_RESISTANT;
    if (is_key_param_suport(KM_TAG_PURPOSE, (void *)&keyblob_purpose, params_hw_enforced) &&
        kb_metafile_write(((keyblob_head *)(input_keyblob->data_addr))->hmac, HMAC_SIZE) != TEE_SUCCESS) {
        tloge("Generate keyblob with rollback resistant failed\n");
        /*
         * To be compatible with google design, we should set the Rollback tag=false
         * and reproduce its HMAC, update the keyblob in future.
         */
        return -1;
    }

    return 0;
}

static int32_t build_keyblob_data(keymaster_blob_t *input_keyblob, TEE_Param *params,
    keymaster_blob_t *keymaterial, keymaster_key_origin_t origin)
{
    keymaster_key_param_set_t *params_hw_enforced = NULL;
    keymaster_key_param_set_t *params_sw_enforced = NULL;
    uint8_t *params_data = NULL;
    int32_t ret;
    if (check_keyblob_buffer_basic(input_keyblob) != KM_ERROR_OK) {
        tloge("wrong keyblob buffer\n");
        return -1;
    }
    if (init_param_sets(&params_hw_enforced, &params_sw_enforced, &params_data, params[PARAM_ZERO]) != 0) {
        tloge("input invalid\n");
        return -1;
    }
    ret = insert_keymaterial(input_keyblob, keymaterial);
    if (ret != 0) {
        tloge("insert keymaterial failed\n");
        return -1;
    }
    ret = build_hw_enforced_datas(origin, params_hw_enforced, input_keyblob, params, keymaterial);
    if (ret != 0) {
        tloge("build_hw_enforced_datas is failed\n");
        return ret;
    }

    ret = fill_enforced_data(input_keyblob, params_hw_enforced, params_sw_enforced, params_data, params);
    if (ret != 0) {
        tloge("fill enforced data failed, ret %d\n", ret);
        return -1;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    /*
     * DO NOT add code after this paragraph! write keyblob metadata (HMAC) into rpmb.
     * IF neccessary, please add 'delete keymaster rollback resistant tag' here.
     */
    ret = build_rpmb_keyblob_data(input_keyblob, params_hw_enforced);
#endif
    return ret;
}

int32_t generate_keyblob(const uint8_t *keymaterial, uint32_t keymaterial_size, keymaster_key_origin_t origin,
    TEE_Param *params, uint32_t version)
{
    /*
     * keyblob:
     * |-- keyblob_head --|-- keymaterial --
     * |--hw_enforced length --|--hw_enforced params[] --
     * |-- sw_enforced length --|--sw_enforced params[] --
     * |--hidden length --|-- hidden params[] -- |--hidden extend buffer--|
     */
    bool check_fail = (params == NULL || keymaterial == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    int32_t ret;
    uint8_t *tmp = (uint8_t *)TEE_Malloc(KEY_BLOB_MAX_SIZE, TEE_MALLOC_FILL_ZERO);
    if (tmp == NULL) {
        tloge("malloc faild\n");
        return -1;
    }

    keyblob_head *keyblob = (keyblob_head *)tmp;
    keyblob->keyblob_total_size = sizeof(keyblob_head);
    keyblob->magic = KM_MAGIC_NUM;
    keyblob->version = version;
    keymaster_blob_t keymaterial_blob = { (uint8_t *)keymaterial, keymaterial_size };
    keymaster_blob_t input_keyblob = { tmp, KEY_BLOB_MAX_SIZE };
    ret = build_keyblob_data(&input_keyblob, params, &keymaterial_blob, origin);
    TEE_Free(tmp);
    tmp = NULL;
    input_keyblob.data_addr = NULL;
    if (ret != 0) {
        tloge("build keyblob data is failed\n");
        return -1;
    }
    tlogd("build keyblob data success\n");
    return 0;
}
