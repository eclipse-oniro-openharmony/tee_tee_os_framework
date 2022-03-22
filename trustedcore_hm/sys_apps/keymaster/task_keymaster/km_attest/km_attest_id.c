/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest id process
 * Create: 2020-11-09
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_common.h"
#include "km_attest.h"
#include "tee_private_api.h"
#include "km_crypto.h"
static keymaster_tag_t g_id_tag_list[] = {
    KM_TAG_ATTESTATION_ID_BRAND,
    KM_TAG_ATTESTATION_ID_DEVICE,
    KM_TAG_ATTESTATION_ID_PRODUCT,
    KM_TAG_ATTESTATION_ID_SERIAL,
    KM_TAG_ATTESTATION_ID_IMEI,
    KM_TAG_ATTESTATION_ID_MEID,
    KM_TAG_ATTESTATION_ID_MANUFACTURER,
    KM_TAG_ATTESTATION_ID_MODEL
};
static uint8_t g_id_identifiers_salt[] = "id_identifiers";
static uint8_t g_id_identifiers_salt_total[] = "id_identifiers_total";

static TEE_Result hmac_identifiers(const uint8_t *salt, uint32_t salt_size, uint8_t *input, uint32_t input_size,
                                   uint8_t *output, uint32_t output_size)
{
    uint8_t hmac_key[AES_KEY_LEN] = { 0 };

    /* derive key */
    if (TEE_EXT_ROOT_DeriveKey2(salt, salt_size, hmac_key, AES_KEY_LEN)) {
        tloge("derive key fromm root key failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (hmac_with_key(hmac_key, input, input_size, output, output_size)) {
        tloge("hmac_with_key failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_identifiers_tag(keymaster_tag_t tag)
{
    uint32_t i;
    bool find  = false;
    uint32_t total = sizeof(g_id_tag_list) / sizeof(g_id_tag_list[0]);

    for (i = 0; i < total; i++) {
        if (tag == g_id_tag_list[i]) {
            find = true;
            break;
        }
    }
    if (find)
        return TEE_SUCCESS;

    tlogd("tag 0x%x is not in list\n", tag);
    return TEE_ERROR_BAD_PARAMETERS;
}

static int32_t check_exist_tag(keymaster_tag_t tag, const struct identifiers_str *value_max, int num)
{
    bool check_fail = ((value_max == NULL) || (num >= ID_IDENTIFIERS_MAX));
    if (check_fail) {
        tloge("invalid input\n");
        return -1;
    }
    int i;
    for (i = 0; i < num; i++)
        if (tag == value_max[i].tag && tag != KM_TAG_ATTESTATION_ID_IMEI)
            return i;
    return -1;
}

static TEE_Result generate_identifiers_sub(identifiers_stored *id)
{
    uint8_t *in  = (uint8_t *)id->id;
    uint8_t *out = id->hmac;
    TEE_Result result = hmac_identifiers(g_id_identifiers_salt_total, sizeof(g_id_identifiers_salt_total), in,
        sizeof(identifiers_hmac) * ID_IDENTIFIERS_MAX, out, HMAC_SHA256_SIZE);
    if (result != TEE_SUCCESS) {
        tloge("hmac failed\n");
        return TEE_ERROR_GENERIC;
    }
    tlogd("generate_identifiers success\n");
    return TEE_SUCCESS;
}

TEE_Result generate_identifiers(const uint8_t *buf, identifiers_stored *id)
{
    if ((buf == NULL) || (id == NULL)) {
        tloge("the buf or id is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result result;
    struct identifiers_str *temp = (struct identifiers_str *)buf;
    int32_t i;
    uint8_t *in = NULL;
    uint8_t *out = NULL;

    /* hmac value from string */
    id->version = ID_IDENTIFIERS_VERSION;
    for (i = 0; i < ID_IDENTIFIERS_MAX; i++) {
        if (check_identifiers_tag(temp[i].tag) != TEE_SUCCESS) {
            tlogd("not attestationeids tag, ignore\n");
            continue;
        }
        id->id[i].tag = temp[i].tag;
        in            = (uint8_t *)temp[i].value;
        out           = id->id[i].hmac;
        /* hmac each identify */
        result = hmac_identifiers(g_id_identifiers_salt, sizeof(g_id_identifiers_salt), in,
                                  PROPERTY_VALUE_MAX, out, HMAC_SHA256_SIZE);
        if (result != TEE_SUCCESS) {
            tloge("hmac failed\n");
            return TEE_ERROR_GENERIC;
        }
        tlogd("tag is 0x%x, value is %s\n", id->id[i].tag, in);
    }
    /* hmac all identifiers */
    return generate_identifiers_sub(id);
}

static int32_t find_value_in_identifiers(const struct identifiers_str *value, const identifiers_stored *stored)
{
    bool condition = ((value == NULL) || (stored == NULL));
    if (condition)
        return 0;

    uint8_t hmac[HMAC_SHA256_SIZE] = { 0 };
    if (hmac_identifiers(g_id_identifiers_salt, sizeof(g_id_identifiers_salt),
                         (uint8_t *)value->value, PROPERTY_VALUE_MAX, hmac, HMAC_SHA256_SIZE)) {
        tloge("hmac failed\n");
        return 0;
    }
    int32_t i;
    int32_t match = 0;
    for (i = 0; i < ID_IDENTIFIERS_MAX; i++) {
        if (value->tag == stored->id[i].tag) {
            tlogd("!!find tag 0x%x in stored\n", value->tag);
            if (!TEE_MemCompare(hmac, stored->id[i].hmac, HMAC_SHA256_SIZE)) {
                tlogd("match value %s hmac in stored\n", value->value);
                match = 1;
                break;
            }
        }
    }
    return match;
}

static TEE_Result compare_identifiers(const struct identifiers_str *value, int32_t num,
    const identifiers_stored *stored)
{
    bool check_fail = ((value == NULL) || (stored == NULL));
    if (check_fail) {
        tloge("the value or stored is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t i;
    for (i = 0; i < num; i++) {
        if (!find_value_in_identifiers(&value[i], stored)) {
            tloge("tag 0x%x does not match\n", value[i].tag);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

static int32_t build_value_ext_part(const keymaster_key_param_t *params,  struct identifiers_str *value_max,
    int32_t *num, const uint8_t *extend_bufer, uint32_t param_index)
{
    int32_t index = check_exist_tag(params[param_index].tag, value_max, *num);
    const uint8_t *src = extend_bufer + params[param_index].blob.data_offset;
    uint32_t size = params[param_index].blob.data_length;
    bool condition = (index >= 0 && index < *num);
    errno_t rc;
    if (condition) {
        value_max[index].tag = params[param_index].tag;
        rc = memcpy_s(value_max[index].value, PROPERTY_VALUE_MAX, src, size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return -1;
        }
    } else {
        value_max[*num].tag = params[param_index].tag;
        rc = memcpy_s(value_max[*num].value, PROPERTY_VALUE_MAX, src, size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return -1;
        }
        *num = *num + 1;
    }
    return 0;
}

static int32_t build_value_ext(const keymaster_key_param_t *params, uint32_t params_len,
    struct identifiers_str *value_max, int32_t *num, uint8_t *extend_bufer)
{
    uint32_t i;
    TEE_Result ret;
    bool condition = ((params == NULL) || (value_max == NULL) || (num == NULL) || (extend_bufer == NULL));
    if (condition) {
        tloge("invalid input\n");
        return -1;
    }
    for (i = 0; i < params_len; i++) {
        if (*num >= ID_IDENTIFIERS_MAX) {
            tloge("num overflow\n");
            return -1;
        }
        ret = check_identifiers_tag(params[i].tag);
        if (ret != TEE_SUCCESS)
            continue;
        ret = (TEE_Result)build_value_ext_part(params, value_max, num, extend_bufer, i);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static int build_value(const keymaster_key_param_set_t *attest_params, struct identifiers_str *value_max)
{
    int32_t num = 0;
    bool check_fail = ((attest_params == NULL) || (value_max == NULL));
    if (check_fail) {
        tloge("the attest_params or value_max is null");
        return -1;
    }
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)attest_params +
                                        sizeof(attest_params->length));
    if (params_hw == NULL) {
        tloge("params_hw is null\n");
        return -1;
    }
    uint32_t hw_enforced_len = *(uint32_t *)attest_params;
    tlogd("hw_enforced_len is %u\n", hw_enforced_len);

    keymaster_key_param_t *params_sw =
        (keymaster_key_param_t *)((uint8_t *)params_hw +
                                  (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null\n");
        return -1;
    }
    uint32_t sw_enforced_len =
        *(uint32_t *)((uint8_t *)params_hw + (hw_enforced_len * sizeof(keymaster_key_param_t)));

    uint8_t *extend_bufer_in =
        (uint8_t *)((uint8_t *)attest_params + sizeof(uint32_t) + (hw_enforced_len * sizeof(keymaster_key_param_t)) +
                    sizeof(uint32_t) + (sw_enforced_len * sizeof(keymaster_key_param_t)));
    if (build_value_ext(params_hw, hw_enforced_len, value_max, &num, extend_bufer_in)) {
        tloge("build hw failed\n");
        return -1;
    }
    if (build_value_ext(params_sw, sw_enforced_len, value_max, &num, extend_bufer_in)) {
        tloge("build sw failed\n");
        return -1;
    }
    return num;
}

static int32_t verify_identifiers_init(const keymaster_key_param_set_t *attest_params,
    struct identifiers_str **value_max, identifiers_stored **local, int32_t *num)
{
    bool check_fail = (local == NULL || value_max == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    /* get value from attest_params */
    *value_max = (struct identifiers_str *)TEE_Malloc(sizeof(struct identifiers_str) * ID_IDENTIFIERS_MAX, 0);
    if (*value_max == NULL) {
        tloge("value_max malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    /* parser identifier value from params */
    *num = build_value(attest_params, *value_max);
    if (*num <= 0) {
        TEE_Free(*value_max);
        *value_max = NULL;
        if (*num == 0) {
            tlogd("no identifiers tag in params\n");
            return 0;
        }
        if (*num == -1) {
            tloge("parser identifier value from params failed\n");
            return -1;
        }
    }
    /* read identifiers stored in TEE */
    *local = read_identifiers();
    if (*local == NULL) {
        tloge("can not get stored identifiers\n");
        TEE_Free(*value_max);
        *value_max = NULL;
        return -1;
    }
    return 1;
}

TEE_Result verify_identifiers_with_param(const keymaster_key_param_set_t *attest_params)
{
    if (attest_params == NULL) {
        tloge("attest_params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    int32_t init_rc;
    int32_t num;
    struct identifiers_str *value_max = NULL;
    identifiers_stored *local = NULL;
    init_rc = verify_identifiers_init(attest_params, &value_max, &local, &num);
    if (init_rc == -1)
        return TEE_ERROR_GENERIC;
    if (init_rc != 1)
        return TEE_SUCCESS;
    /* verify identifiers stored in TEE */
    uint8_t hmac[HMAC_SHA256_SIZE] = { 0 };
    ret = hmac_identifiers(g_id_identifiers_salt_total, sizeof(g_id_identifiers_salt_total), (uint8_t *)local->id,
                           sizeof(identifiers_hmac) * ID_IDENTIFIERS_MAX, hmac, HMAC_SHA256_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("hmac_identifiers failed\n");
        ret = TEE_ERROR_GENERIC;
        goto release;
    }
    int32_t rc = TEE_MemCompare(hmac, local->hmac, HMAC_SHA256_SIZE);
    if (rc != 0) {
        tloge("identifiers stored in TEE is invalid\n");
        ret = TEE_ERROR_GENERIC;
        goto release;
    }
    /* compare identifiers stored in TEE */
    ret = compare_identifiers(value_max, num, local);
    if (ret != TEE_SUCCESS) {
        tloge("compare_identifiers failed\n");
        ret = TEE_ERROR_GENERIC;
    } else {
        ret = TEE_SUCCESS;
    }
release:
    TEE_Free(value_max);
    TEE_Free(local);
    return ret;
}

static uint32_t count_attestation_ids(const keymaster_key_param_t *params, uint32_t len, uint8_t *extend_bufer_in)
{
    bool check_fail = ((params == NULL) || (extend_bufer_in == NULL));
    if (check_fail) {
        tloge("the parameter params or extend_bufer_in is null\n");
        return 0;
    }

    uint32_t size = 0;
    uint32_t i;
    for (i = 0; i < len; i++) {
        switch (params[i].tag) {
        case KM_TAG_ATTESTATION_ID_BRAND:
        case KM_TAG_ATTESTATION_ID_DEVICE:
        case KM_TAG_ATTESTATION_ID_PRODUCT:
        case KM_TAG_ATTESTATION_ID_SERIAL:
        case KM_TAG_ATTESTATION_ID_IMEI:
        case KM_TAG_ATTESTATION_ID_MEID:
        case KM_TAG_ATTESTATION_ID_MANUFACTURER:
        case KM_TAG_ATTESTATION_ID_MODEL:
            size += params[i].blob.data_length;
            break;
        default:
            break;
        }
    }
    return size;
}

uint32_t attestationids_len(const keymaster_key_param_set_t *attest_params)
{
    if (attest_params == NULL) {
        tloge("the parameter attest_params is null\n");
        return 0;
    }
    uint32_t total_len = 0;

    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)attest_params +
                                        sizeof(attest_params->length));
    if (params_hw == NULL) {
        tloge("params_hw is null\n");
        return 0;
    }
    uint32_t hw_enforced_len = *(uint32_t *)attest_params;
    tlogd("hw_enforced_len is %u\n", hw_enforced_len);

    keymaster_key_param_t *params_sw =
        (keymaster_key_param_t *)((uint8_t *)params_hw +
                                  (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null\n");
        return 0;
    }
    uint32_t sw_enforced_len = *(uint32_t *)((uint8_t *)params_hw + (hw_enforced_len * sizeof(keymaster_key_param_t)));

    uint8_t *extend_bufer_in = (uint8_t *)((uint8_t *)params_sw + (sw_enforced_len * sizeof(keymaster_key_param_t)));
    total_len += count_attestation_ids(params_hw, hw_enforced_len, extend_bufer_in);
    total_len += count_attestation_ids(params_sw, sw_enforced_len, extend_bufer_in);
    return total_len;
}

#define set_auth_list_tag_data(tag) do { auth_list->tag.tag_set = 1; \
    auth_list->tag.blob.data_addr = (extend_bufer_in + params[i].blob.data_offset); \
    auth_list->tag.blob.data_length = params[i].blob.data_length; } while (0)
void build_authlist(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t len,
    uint8_t *extend_bufer_in)
{
    uint32_t i;
    bool check = ((auth_list == NULL) || (params == NULL) || (extend_bufer_in == NULL));
    if (check) {
        tloge("auth_list or params or extend_bufer_in is null\n");
        return;
    }

    for (i = 0; i < len; i++) {
        switch (params[i].tag) {
        case KM_TAG_ATTESTATION_ID_BRAND:
            set_auth_list_tag_data(attestation_id_brand);
            break;
        case KM_TAG_ATTESTATION_ID_DEVICE:
            set_auth_list_tag_data(attestation_id_device);
            break;
        case KM_TAG_ATTESTATION_ID_PRODUCT:
            set_auth_list_tag_data(attestation_id_product);
            break;
        case KM_TAG_ATTESTATION_ID_SERIAL:
            set_auth_list_tag_data(attestation_id_serial);
            break;
        case KM_TAG_ATTESTATION_ID_IMEI:
            auth_list->attestation_id_imei.count = auth_list->attestation_id_imei.count % IMEI_MAX;
            auth_list->attestation_id_imei.count++;
            auth_list->attestation_id_imei.blob[auth_list->attestation_id_imei.count].data_addr =
                extend_bufer_in + params[i].blob.data_offset;
            auth_list->attestation_id_imei.blob[auth_list->attestation_id_imei.count].data_length =
                params[i].blob.data_length;
            break;
        case KM_TAG_ATTESTATION_ID_MEID:
            set_auth_list_tag_data(attestation_id_meid);
            break;
        case KM_TAG_ATTESTATION_ID_MANUFACTURER:
            set_auth_list_tag_data(attestation_id_manufacturer);
            break;
        case KM_TAG_ATTESTATION_ID_MODEL:
            set_auth_list_tag_data(attestation_id_model);
            break;
        default:
            break;
        }
    }
}
