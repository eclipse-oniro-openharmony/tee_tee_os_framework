/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cms signature auth
 * Author: wangchunxu1@huawei.com
 * Create: 2020.06.18
 */

#include "tee_auth_sign_cms.h"
#include "cms_signature_verify.h"
#include "tee_log.h"
#include <string.h>

#define SHA256_HASH_LEN 32
#define STR_TO_HEX_BYTE 2
#define BIT_4           4
#define BYTE_HIGH_BIT_4 0xF0
#define IS_BETWEEN_VALUE(value, min, max)  (((value) >= (min)) && ((value) <= (max)))
#define CAL_CHAR_VALUE(value, min, inc)    ((value) - (min) + (inc))

static char ch2hex(char c)
{
    if (IS_BETWEEN_VALUE(c, '0', '9')) {
        return CAL_CHAR_VALUE(c, '0', 0);
    } else if (IS_BETWEEN_VALUE(c, 'a', 'f')) {
        return CAL_CHAR_VALUE(c, 'a', 10);
    } else if (IS_BETWEEN_VALUE(c, 'A', 'F')) {
        return CAL_CHAR_VALUE(c, 'A', 10);
    } else {
        tloge("CMSCBB: Error! Input is not a hex value!");
        return 0;
    }
}

static TEE_Result str2hex(const uint8_t *str, uint32_t str_len, uint8_t *hex, uint32_t hex_len)
{
    bool check_params = ((str == NULL) || (hex == NULL) || (str_len != hex_len * STR_TO_HEX_BYTE));
    if (check_params) {
        tloge("CMSCBB: input param is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (uint32_t i = 0; i < str_len; i += STR_TO_HEX_BYTE)
        *(hex + i / STR_TO_HEX_BYTE) = ((((uint8_t)ch2hex(*(str + i)) << BIT_4) & BYTE_HIGH_BIT_4) +
                                        (uint8_t)ch2hex(*(str + i + 1)));

    return TEE_SUCCESS;
}

static TEE_Result check_ini_with_hash(const struct cms_sign_info *sign_info, const uint8_t *hash_buf, size_t hash_len)
{
    uint8_t hash_in_ini[SHA256_HASH_LEN] = {0};
    TEE_Result ret = str2hex(sign_info->ini_buf + CONFIG_INI_TAG_LEN, SHA256_HASH_LEN * STR_TO_HEX_BYTE,
                             hash_in_ini, SHA256_HASH_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("CMSCBB: convert str to hex failed (0x%x)\n", ret);
        return ret;
    }

    int res = memcmp((const void *)hash_in_ini, (const void *)hash_buf, hash_len);
    if (res != 0) {
        tloge("CMSCBB: compare hash failed %d\n", res);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result verify_cms_signature(const uint8_t *hash_buf, size_t hash_len, const uint8_t *sig_buf, uint32_t sig_len)
{
    bool check_params = (hash_buf == NULL || hash_len != SHA256_HASH_LEN || sig_buf == NULL ||
                         sig_len != (CONFIG_CMS_DATA_SIZE + CONFIG_INI_DATA_SIZE + CONFIG_CRL_DATA_SIZE));
    if (check_params) {
        tloge("CMSCBB: invalid params for cms verify\n");
        return TEE_ERROR_GENERIC;
    }

    struct cms_sign_info sign_info = {0};
    sign_info.sig_buf = (uint8_t *)sig_buf;
    sign_info.sig_len = sig_len;

    sign_info.cms_header = sign_info.sig_buf;
    sign_info.cms_buf = sign_info.cms_header + CONFIG_CMS_HEADER_LEN;
    sign_info.cms_len = *(uint32_t *)(uintptr_t)(sign_info.cms_header + CONFIG_CMS_HEADER_NAME_LEN);

    sign_info.ini_header = sign_info.cms_header + CONFIG_CMS_DATA_SIZE;
    sign_info.ini_buf = sign_info.ini_header + CONFIG_CMS_HEADER_LEN;
    sign_info.ini_len = *(uint32_t *)(uintptr_t)(sign_info.ini_header + CONFIG_CMS_HEADER_NAME_LEN);

    sign_info.crl_header = sign_info.ini_header + CONFIG_INI_DATA_SIZE;
    sign_info.crl_buf = sign_info.crl_header + CONFIG_CMS_HEADER_LEN;
    sign_info.crl_len = *(uint32_t *)(uintptr_t)(sign_info.crl_header + CONFIG_CMS_HEADER_NAME_LEN);

    bool check_lens = (sign_info.cms_len > (CONFIG_CMS_DATA_SIZE - CONFIG_CMS_HEADER_LEN) ||
                       sign_info.ini_len > (CONFIG_INI_DATA_SIZE - CONFIG_CMS_HEADER_LEN) ||
                       sign_info.crl_len > (CONFIG_CRL_DATA_SIZE - CONFIG_CMS_HEADER_LEN));
    if (check_lens) {
        tloge("CMSCBB: invalid sign data lens for cms verify\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result check_state = check_ini_with_hash(&sign_info, hash_buf, hash_len);
    if (check_state != TEE_SUCCESS) {
        tloge("CMSCBB: check ini with hash failed (0x%x)\n", check_state);
        return check_state;
    }

    check_state = (TEE_Result)check_cms_signature(&sign_info);
    if (check_state != TEE_SUCCESS) {
        tloge("CMSCBB: check cms with ini failed (0x%x)\n", check_state);
        return check_state;
    }

    return check_state;
}
