/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key params operation
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "securec.h"
#include "km_common.h"
#include "km_types.h"
#include "keyblob.h"
static int32_t copy_km_param(keymaster_key_param_t *to, uint8_t *to_extend, uint32_t *to_extend_len,
    uint32_t extend_size, const keymaster_key_param_t *from, const uint8_t *from_extend)
{
    bool check_fail =
        (to_extend == NULL || to_extend_len == NULL || from_extend == NULL || to == NULL || from == NULL);
    if (check_fail) {
        tloge("input is null\n");
        return -1;
    }
    if (memcpy_s(to, sizeof(keymaster_key_param_t), from, sizeof(keymaster_key_param_t)) != EOK) {
        tloge("copy param failed\n");
        return -1;
    }
    uint32_t to_extend_offset = *to_extend_len;
    if (keymaster_tag_get_type(from->tag) == KM_BIGNUM || keymaster_tag_get_type(from->tag) == KM_BYTES) {
        if (memcpy_s(to_extend + to_extend_offset, extend_size - to_extend_offset,
                     from_extend + from->blob.data_offset, from->blob.data_length) != EOK) {
            tloge("copy params's buffer failed\n");
            return -1;
        }
        to->blob.data_offset = to_extend_offset;
        *to_extend_len += from->blob.data_length;
    }

    return 0;
}

static bool hardware_enforced_tag(keymaster_tag_t tag)
{
    keymaster_tag_t hw_enforced_tag_list[] = {
        KM_TAG_PURPOSE, KM_TAG_ALGORITHM, KM_TAG_KEY_SIZE, KM_TAG_BLOCK_MODE,
        KM_TAG_DIGEST, KM_TAG_PADDING, KM_TAG_KDF, KM_TAG_EC_CURVE,
        KM_TAG_RSA_PUBLIC_EXPONENT, KM_TAG_UNIQUE_ID, KM_TAG_INCLUDE_UNIQUE_ID, KM_TAG_BLOB_USAGE_REQUIREMENTS,
        KM_TAG_BOOTLOADER_ONLY, KM_TAG_ACTIVE_DATETIME, KM_TAG_AUTH_TIMEOUT, KM_TAG_USAGE_EXPIRE_DATETIME,
        KM_TAG_MIN_SECONDS_BETWEEN_OPS, KM_TAG_MAX_USES_PER_BOOT, KM_TAG_USER_SECURE_ID, KM_TAG_NO_AUTH_REQUIRED,
        KM_TAG_USER_AUTH_TYPE, KM_TAG_ALLOW_WHILE_ON_BODY, KM_TAG_ALL_APPLICATIONS, KM_TAG_ORIGINATION_EXPIRE_DATETIME,
        KM_TAG_EXPORTABLE, KM_TAG_CREATION_DATETIME, KM_TAG_ORIGIN, KM_TAG_ROLLBACK_RESISTANCE,
        KM_TAG_ROLLBACK_RESISTANT, KM_TAG_OS_VERSION, KM_TAG_OS_PATCHLEVEL, KM_TAG_ECIES_SINGLE_HASH_MODE,
        KM_TAG_ATTESTATION_CHALLENGE, KM_TAG_AUTH_TOKEN, KM_TAG_MAC_LENGTH, KM_TAG_RESET_SINCE_ID_ROTATION,
        KM_TAG_HARDWARE_TYPE, KM_TAG_TRUSTED_CONFIRMATION_REQUIRED, KM_TAG_VENDOR_PATCHLEVEL, KM_TAT_BOOT_PATCHLEVEL,
        KM_TAG_CONFIRMATION_TOKEN, KM_TAG_UNLOCKED_DEVICE_REQUIRED, KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
    };
    uint32_t i;
    for (i = 0; i < sizeof(hw_enforced_tag_list) / sizeof(keymaster_tag_t); i++) {
        if (tag == hw_enforced_tag_list[i])
            return true;
    }
    return false;
}

static int32_t copy_hw_enforced_data_from_old_hw_enforce(const keymaster_key_param_set_t *hw_params_set,
    keymaster_key_param_set_t *new_hw_params_set, uint8_t *dst, uint32_t extend_base, uint32_t *extend_cp_len,
    uint32_t size, const uint8_t *src)
{
    uint32_t i;
    keymaster_key_param_t *hw_params = NULL;
    keymaster_key_param_t *new_hw_params = (keymaster_key_param_t *)((uint8_t *)new_hw_params_set + sizeof(uint32_t));
    if (hw_params_set->length != 0)
        hw_params = (keymaster_key_param_t *)((uint8_t *)hw_params_set + sizeof(hw_params_set->length));
    for (i = 0; i < hw_params_set->length; i++) {
        if ((hw_params != NULL) && hardware_enforced_tag(hw_params[i].tag)) {
            if (copy_km_param(&new_hw_params[new_hw_params_set->length], dst + extend_base,
                extend_cp_len, size, &hw_params[i], src + extend_base) != 0) {
                tloge("copy hw_params[%u](tag=%d) to hw_enforced failed\n", i, hw_params[i].tag);
                return -1;
            }
            new_hw_params_set->length++;
        }
    }

    return 0;
}

static int32_t copy_hw_enforced_data_from_old_sw_enforce(const keymaster_key_param_set_t *sw_params_set,
    keymaster_key_param_set_t *new_hw_params_set, uint8_t *dst, uint32_t extend_base, uint32_t *extend_cp_len,
    uint32_t size, const uint8_t *src)
{
    uint32_t i;
    keymaster_key_param_t *sw_params = NULL;
    keymaster_key_param_t *new_hw_params = (keymaster_key_param_t *)((uint8_t *)new_hw_params_set + sizeof(uint32_t));
    if (sw_params_set->length != 0)
        sw_params = (keymaster_key_param_t *)((uint8_t *)sw_params_set + sizeof(sw_params_set->length));
    for (i = 0; i < sw_params_set->length; i++) {
        if ((sw_params != NULL) && hardware_enforced_tag(sw_params[i].tag)) {
            if (copy_km_param(&new_hw_params[new_hw_params_set->length], dst + extend_base,
                extend_cp_len, size, &sw_params[i], src + extend_base) != 0) {
                tloge("copy sw_params[%u](tag=%d) to hw_enforced failed\n", i, sw_params[i].tag);
                return -1;
            }
            new_hw_params_set->length++;
        }
    }

    return 0;
}

static int32_t copy_hw_enforced_data(const keymaster_key_param_set_t *hw_params_set,
    const keymaster_key_param_set_t *sw_params_set, keymaster_key_param_set_t *new_hw_params_set, uint8_t *dst,
    uint32_t extend_base, uint32_t *extend_cp_len, uint32_t size, const uint8_t *src)
{
    int32_t ret;
    ret = copy_hw_enforced_data_from_old_hw_enforce(hw_params_set, new_hw_params_set, dst, extend_base, extend_cp_len,
        size, src);
    if (ret != 0)
        return ret;

    ret = copy_hw_enforced_data_from_old_sw_enforce(sw_params_set, new_hw_params_set, dst, extend_base, extend_cp_len,
        size, src);
    if (ret != 0)
        return ret;

    return 0;
}

static int32_t copy_sw_enforced_data(const keymaster_key_param_set_t *hw_params_set,
    const keymaster_key_param_set_t *sw_params_set, keymaster_key_param_set_t *new_sw_params_set, uint8_t *dst,
    uint32_t extend_base, uint32_t *extend_cp_len, uint32_t size, const uint8_t *src)
{
    uint32_t i;
    keymaster_key_param_t *hw_params = NULL;
    keymaster_key_param_t *sw_params = NULL;
    keymaster_key_param_t *new_sw_params = (keymaster_key_param_t *)((uint8_t *)new_sw_params_set + sizeof(uint32_t));
    if (hw_params_set->length != 0)
        hw_params = (keymaster_key_param_t *)((uint8_t *)hw_params_set + sizeof(hw_params_set->length));
    if (sw_params_set->length != 0)
        sw_params = (keymaster_key_param_t *)((uint8_t *)sw_params_set + sizeof(sw_params_set->length));
    /* copy sw_enforced from old hw_enforce */
    for (i = 0; i < hw_params_set->length; i++) {
        if ((hw_params != NULL) && !hardware_enforced_tag(hw_params[i].tag)) {
            if (copy_km_param(&new_sw_params[new_sw_params_set->length], dst + extend_base,
                extend_cp_len, size, &hw_params[i], src + extend_base) != 0) {
                tloge("copy hw_params[%u](tag=%d) to sw_enforced failed\n", i, hw_params[i].tag);
                return -1;
            }
            new_sw_params_set->length++;
        }
    }

    /* copy sw_enforced from old sw_enforce */
    for (i = 0; i < sw_params_set->length; i++) {
        if ((sw_params != NULL) && !hardware_enforced_tag(sw_params[i].tag)) {
            if (copy_km_param(&new_sw_params[new_sw_params_set->length], dst + extend_base,
                extend_cp_len, size, &sw_params[i], src + extend_base) != 0) {
                tloge("copy sw_params[%u](tag=%d) to sw_enforced failed\n", i, sw_params[i].tag);
                return -1;
            }
            new_sw_params_set->length++;
        }
    }

    return 0;
}

static int32_t set_and_check_hw_sw_paramset(const uint8_t *src, uint32_t size,
    keymaster_key_param_set_t **hw_params_set, keymaster_key_param_set_t **sw_params_set, uint32_t *extend_base)
{
    bool check_fail = (src == NULL || hw_params_set == NULL || sw_params_set == NULL || extend_base == NULL ||
        size < sizeof(keymaster_key_param_set_t) * KM_FACTOR_2);
    if (check_fail) {
        tloge("invalid paramset parameters \n");
        return -1;
    }
    *hw_params_set = (keymaster_key_param_set_t *)src;
    check_fail = (((size - sizeof((*hw_params_set)->length)) / sizeof(keymaster_key_param_t)) <
        (*hw_params_set)->length ||
        (size - (*hw_params_set)->length * sizeof(keymaster_key_param_t) - sizeof((*hw_params_set)->length)) <
        sizeof(keymaster_key_param_set_t));
    if (check_fail) {
        tloge("invalid hw paramset buffer, hw param length %u, total len %u\n", (*hw_params_set)->length, size);
        return -1;
    }

    *sw_params_set = (keymaster_key_param_set_t *)(src + sizeof((*hw_params_set)->length) +
        (*hw_params_set)->length * sizeof(keymaster_key_param_t));
    if ((*sw_params_set) == NULL) {
        tloge("sw_params_set is null\n");
        return -1;
    }
    if ((size - (*hw_params_set)->length * sizeof(keymaster_key_param_t) - sizeof((*hw_params_set)->length) -
        sizeof((*sw_params_set)->length)) / sizeof(keymaster_key_param_t) < (*sw_params_set)->length) {
        tloge("invalid sw paramset buffer, sw param length %u, total buff len %u\n", (*sw_params_set)->length, size);
        return -1;
    }
    *extend_base = ((*hw_params_set)->length * sizeof(keymaster_key_param_t) + sizeof((*hw_params_set)->length) +
        sizeof((*sw_params_set)->length) * sizeof(keymaster_key_param_t) + (*sw_params_set)->length);
    return 0;
}

/*
 * params set should be checked by key_param_set_check() function, output characteristics format:
 * |- hw_enforced->length -|- hw_enforced params(maybe NULL) -|
 * |- sw_enforced->length -|- sw_enforced params(mabye NULL) -|
 * |- hw_enforced params data -|- sw_enforced params data -|
 */
int32_t resort_key_characteristics(uint8_t *dst, const uint8_t *src, uint32_t size)
{
    uint32_t extend_cp_len = 0;
    if (dst == NULL || src == NULL || size < sizeof(uint32_t) * KM_FACTOR_2) {
        tloge("invalid paramset parameters \n");
        return -1;
    }
    keymaster_key_param_set_t *hw_params_set = (keymaster_key_param_set_t *)src;
    keymaster_key_param_set_t *sw_params_set = NULL;
    uint32_t extend_base = 0;
    if (set_and_check_hw_sw_paramset(src, size, &hw_params_set, &sw_params_set, &extend_base) != 0) {
        tloge("set and check paramsets failed\n");
        return -1;
    }
    /* init for new hw_enforced params set */
    keymaster_key_param_set_t *new_hw_params_set = (keymaster_key_param_set_t *)dst;
    new_hw_params_set->length = 0;

    /* copy hw_enforced from old hw_enforce, copy hw_enforced from old sw_enforce */
    if (copy_hw_enforced_data(hw_params_set, sw_params_set, new_hw_params_set, dst,
        extend_base, &extend_cp_len, size, src) != 0) {
        tloge("copy_hw_enforced_data is failed\n");
        return -1;
    }

    /* init for new hw_enforced params set */
    keymaster_key_param_set_t *new_sw_params_set = (keymaster_key_param_set_t *)(dst +
        sizeof(new_hw_params_set->length) + new_hw_params_set->length * sizeof(keymaster_key_param_t));

    new_sw_params_set->length = 0;
    /* copy sw_enforced from old hw_enforce, copy sw_enforced from old sw_enforce */
    if (copy_sw_enforced_data(hw_params_set, sw_params_set, new_sw_params_set, dst, extend_base,
        &extend_cp_len, size, src) != 0) {
        tloge("copy_sw_enforced_data is failed\n");
        return -1;
    }
    return 0;
}
