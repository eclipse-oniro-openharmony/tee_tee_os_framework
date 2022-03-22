/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer for different cipher engine
 * Create: 2020-11-09
 */
#include "securec.h"
#include "km_types.h"
#include "crypto_wrapper.h"
#include "km_key_gp_sw_convert.h"
static int32_t get_attr_index_by_id(uint32_t id, const TEE_Attribute *attrs, uint32_t attr_count)
{
    uint32_t i;
    if (attrs == NULL)
        return -1;
    for (i = 0; i < attr_count; i++) {
        if (id == attrs[i].attributeID)
            return i;
    }
    return -1;
}

static TEE_Result copy_single_key_from_object(const TEE_ObjectHandle object, uint32_t id, uint8_t *key,
    uint32_t *key_len)
{
    int32_t index = get_attr_index_by_id(id, object->Attribute, object->attributesLen);
    if (index < 0) {
        tloge("invalid key, id = 0x%x", id);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    errno_t res = memcpy_s(key, *key_len,
        object->Attribute[index].content.ref.buffer, object->Attribute[index].content.ref.length);
    if (res != EOK) {
        tloge("memcpy 0x%x failed", id);
        return TEE_ERROR_SECURITY;
    }
    *key_len = object->Attribute[index].content.ref.length;
    return TEE_SUCCESS;
}

TEE_Result covert_ec_prvkey_gp2sw(TEE_ObjectHandle key, ecc_priv_key_t *ecc_priv_key)
{
    TEE_Result ret;
    if (ecc_priv_key == NULL || key == TEE_HANDLE_NULL) {
        tloge("null pointers.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_priv_key->r_len = ECC_KEY_LEN;
    ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PRIVATE_VALUE, ecc_priv_key->r, &(ecc_priv_key->r_len));
    if (ret != TEE_SUCCESS)
        return ret;

    int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, key->Attribute, key->attributesLen);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ec_nist_curve2swcurve((TEE_ECC_CURVE)key->Attribute[index].content.value.a, &(ecc_priv_key->domain)) != 0) {
        tloge("convert ec domain to sw failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result covert_ec_pubkey_gp2sw(TEE_ObjectHandle key, ecc_pub_key_t *ecc_pub_key)
{
    TEE_Result ret;
    if (ecc_pub_key == NULL || key == TEE_HANDLE_NULL) {
        tloge("null pointers.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_pub_key->x_len = ECC_KEY_LEN;
    ecc_pub_key->y_len = ECC_KEY_LEN;
    int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, key->Attribute, key->attributesLen);
    if (index < 0) {
        tloge("no ecc curve attr");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ec_nist_curve2swcurve((TEE_ECC_CURVE)key->Attribute[index].content.value.a, &(ecc_pub_key->domain)) != 0) {
        tloge("convert ec domain to sw failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecc_pub_key->x, &(ecc_pub_key->x_len));
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecc_pub_key->y, &(ecc_pub_key->y_len));
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

TEE_Result covert_rsa_prvkey_gp2sw(TEE_ObjectHandle key, rsa_priv_key_t *rsa_priv_key)
{
    TEE_Result ret;
    if (rsa_priv_key == NULL || key == TEE_HANDLE_NULL) {
        tloge("null pointers.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rsa_priv_key->e_len = sizeof(rsa_priv_key->e);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_priv_key->e, &(rsa_priv_key->e_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->n_len = sizeof(rsa_priv_key->n);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_MODULUS, rsa_priv_key->n, &(rsa_priv_key->n_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->d_len = 0;
    rsa_priv_key->p_len = sizeof(rsa_priv_key->p);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PRIME1, rsa_priv_key->p, &(rsa_priv_key->p_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->q_len = sizeof(rsa_priv_key->q);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PRIME2, rsa_priv_key->q, &(rsa_priv_key->q_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->dp_len = sizeof(rsa_priv_key->dp);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_EXPONENT1, rsa_priv_key->dp, &(rsa_priv_key->dp_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->dq_len = sizeof(rsa_priv_key->dq);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_EXPONENT2, rsa_priv_key->dq, &(rsa_priv_key->dq_len));
    if (ret != TEE_SUCCESS)
        return ret;

    rsa_priv_key->qinv_len = sizeof(rsa_priv_key->qinv);
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_COEFFICIENT, rsa_priv_key->qinv, &(rsa_priv_key->qinv_len));
    if (ret != TEE_SUCCESS)
        return ret;
    return TEE_SUCCESS;
}
