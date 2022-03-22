/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer between GP and software engine;
 * Create: 2020-11-09
 */

#include "crypto_wrapper.h"
#include "km_key_gp_sw_convert.h"
static TEE_Result fill_gp_key(TEE_ObjectHandle key_obj, ecc_pub_key_t *sw_pubkey_ec)
{
    size_t y_len = sizeof(sw_pubkey_ec->y);
    TEE_Result ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_Y, sw_pubkey_ec->y, &y_len);
    if (ret != TEE_SUCCESS) {
        tloge("get ec pub key y failed\n");
        return TEE_ERROR_GENERIC;
    }
    sw_pubkey_ec->y_len = (uint32_t)y_len;
    uint32_t gp_ec_domain = 0;
    ret = TEE_GetObjectValueAttribute(key_obj, TEE_ATTR_ECC_CURVE, &gp_ec_domain, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("get ec domain failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (ec_nist_curve2swcurve((TEE_ECC_CURVE)gp_ec_domain, &(sw_pubkey_ec->domain)) != 0) {
        tloge("convert ec domain to sw failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result convert_ec_gp2sw_key(TEE_ObjectHandle key_obj, ecc_pub_key_t *sw_pubkey_ec)
{
    bool check_fail = (key_obj == TEE_HANDLE_NULL || sw_pubkey_ec == NULL || key_obj->ObjectInfo == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    key_obj->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    TEE_Result ret = TEE_RestrictObjectUsage1(key_obj, key_obj->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return TEE_ERROR_GENERIC;
    }
    size_t x_len = sizeof(sw_pubkey_ec->x);
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_X, sw_pubkey_ec->x, &x_len);
    if (ret != TEE_SUCCESS) {
        tloge("get ec pub key x failed\n");
        return TEE_ERROR_GENERIC;
    }
    sw_pubkey_ec->x_len = (uint32_t)x_len;
    return fill_gp_key(key_obj, sw_pubkey_ec);
}

TEE_Result rsa_get_pub_local(rsa_pub_key_t *sw_pubkey_rsa, TEE_ObjectHandle *key_obj)
{
    /* key_obj and  sw_pubkey_rsa should be always be vaild */
    bool check_fail = (key_obj == NULL || sw_pubkey_rsa == NULL);
    if (check_fail)
        return TEE_ERROR_BAD_PARAMETERS;
    size_t n_len = sizeof(sw_pubkey_rsa->n);
    TEE_Result ret = TEE_GetObjectBufferAttribute(*key_obj, TEE_ATTR_RSA_MODULUS, sw_pubkey_rsa->n, &n_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub key modulus failed\n");
        return ret;
    }
    sw_pubkey_rsa->n_len = (uint32_t)n_len;
    size_t e_len = sizeof(sw_pubkey_rsa->e);
    ret = TEE_GetObjectBufferAttribute(*key_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, sw_pubkey_rsa->e, &e_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exponent failed\n");
        return ret;
    }
    sw_pubkey_rsa->e_len = (uint32_t)e_len;
    return ret;
}