/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster old keyblob including dx keyblob transfer to gp format keyblob
 * Create: 2020-08-21
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_dx_key_struct.h"
#include "crypto_wrapper.h"
#include "tee_private_api.h"
#include "keyblob.h"
#include "km_tag_operation.h"
#include "km_crypto_adaptor.h"
/* tlv memory store:  (uint32_t)type | (uint32_t)len | (uint8_t *)value */
static TEE_Result add_tlv_data(uint8_t *out_buf, uint32_t out_len, uint32_t type, uint32_t len, const uint8_t *value)
{
    int32_t rc;
    bool check = (out_buf == NULL || value == NULL);
    if (check) {
        tloge("add tlv data: make tlv, point is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (out_len < (len + KM_TLV_HEAD_LEN)) {
        tloge("add tlv data: bufferlen not enough, out_len = %u, length = %u", out_len, len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *(uint32_t *)out_buf = type;
    *(uint32_t *)(out_buf + sizeof(int32_t)) = len;

    rc = memcpy_s(out_buf + KM_TLV_HEAD_LEN, out_len - KM_TLV_HEAD_LEN, value, len);
    if (rc != EOK) {
        tloge("add tlv data: make tlv error when mem copy");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static uint32_t get_gp_ec_domain(enum DX_EC_DOMAIN_ID domain)
{
    uint32_t index = 0;
    keymaster_uint2uint ec_domain_dx_to_sw[] = {
        { DX_EC_DOMAIN_ID_SECP192R1, TEE_ECC_CURVE_NIST_P192 },
        { DX_EC_DOMAIN_ID_SECP224R1, TEE_ECC_CURVE_NIST_P224 },
        { DX_EC_DOMAIN_ID_SECP256R1, TEE_ECC_CURVE_NIST_P256 },
        { DX_EC_DOMAIN_ID_SECP384R1, TEE_ECC_CURVE_NIST_P384 },
        { DX_EC_DOMAIN_ID_SECP521R1, TEE_ECC_CURVE_NIST_P521 }
    };

    for (; index < (sizeof(ec_domain_dx_to_sw) / sizeof(ec_domain_dx_to_sw[0])); index++)
        if (domain == ec_domain_dx_to_sw[index].src)
            return ec_domain_dx_to_sw[index].dest;
    tloge("get sw do main:invalid domain id %d\n", domain);
    return KM_INVALID_VALUE;
}

static uint32_t ec_dx_domain_id_to_keysize(enum DX_EC_DOMAIN_ID domain)
{
    uint32_t index = 0;
    keymaster_uint2uint ec_domain_to_keysize[] = {
        { DX_EC_DOMAIN_ID_SECP192R1, 192 },
        { DX_EC_DOMAIN_ID_SECP224R1, 224 },
        { DX_EC_DOMAIN_ID_SECP256R1, 256 },
        { DX_EC_DOMAIN_ID_SECP384R1, 384 },
        { DX_EC_DOMAIN_ID_SECP521R1, 521 }
    };

    for (; index < (sizeof(ec_domain_to_keysize) / sizeof(ec_domain_to_keysize[0])); index++)
        if (domain == ec_domain_to_keysize[index].src)
            return ec_domain_to_keysize[index].dest;
    tloge("get key size: invalid domain id %d\n", domain);
    return KM_INVALID_VALUE;
}

static TEE_Result add_rsa_sw_one_attr(const keymaster_blob_t *rsa_key, uint32_t *offset_len, uint32_t att_type,
    uint8_t *out_buff, uint32_t *out_len, uint32_t *attr_len)
{
    if (rsa_key->data_length < *offset_len + sizeof(*attr_len)) {
        tloge("rsa key to gp: len error %u", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *attr_len = *(uint32_t *)(rsa_key->data_addr + *offset_len);
    *offset_len += sizeof(*attr_len);
    if (rsa_key->data_length < *offset_len + *attr_len) {
        tloge("add rsa sw one attr: len error %u", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = add_tlv_data(out_buff, *out_len, att_type, *attr_len, rsa_key->data_addr + *offset_len);
    if (ret != TEE_SUCCESS) {
        tloge("add rsa sw one attr:add tlv data fail");
        return ret;
    }
    *offset_len += *attr_len;
    *out_len = *out_len - *attr_len - KM_TLV_HEAD_LEN;
    return ret;
}

static TEE_Result exchange_e_n_sequnce(keymaster_blob_t *rsa_key)
{
    uint32_t e_attr_len = 0;
    uint8_t tmp_buff[MAX_KEY_BUFFER_LEN] = {0};
    if (rsa_key->data_length < sizeof(e_attr_len)) {
        tloge("length too short %u", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    e_attr_len = *(uint32_t *)(rsa_key->data_addr);
    tlogd("e attr_len %u\n", e_attr_len);
    if (rsa_key->data_length - sizeof(e_attr_len) < e_attr_len) {
        tloge("length %u too short", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(tmp_buff, MAX_KEY_BUFFER_LEN, rsa_key->data_addr, e_attr_len + sizeof(e_attr_len)) != EOK) {
        tloge("copy old rsa key exponent value failed\n");
        return TEE_ERROR_GENERIC;
    }
    uint32_t n_offset = e_attr_len + sizeof(e_attr_len);
    if (rsa_key->data_length - n_offset < sizeof(uint32_t)) {
        tloge("length too short %u", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t n_attr_len = *(uint32_t *)(rsa_key->data_addr + n_offset);
    tlogd("n attr_len %u\n", n_attr_len);
    if (rsa_key->data_length - n_offset - sizeof(e_attr_len) < e_attr_len) {
        tloge("length %u too short", rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memmove_s(rsa_key->data_addr, sizeof(e_attr_len) + e_attr_len + sizeof(n_attr_len) + n_attr_len,
        rsa_key->data_addr + n_offset, sizeof(n_attr_len) + n_attr_len) != EOK) {
        tloge("move attr n to the front failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (memcpy_s(rsa_key->data_addr + sizeof(n_attr_len) + n_attr_len, sizeof(e_attr_len) + e_attr_len,
        tmp_buff, sizeof(e_attr_len) + e_attr_len) != EOK) {
        tloge("copy attr e behind n failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result rsa_key_sw2gp(keymaster_blob_t *rsa_key, keymaster_blob_t *gp_key, uint32_t *is_crt)
{
    TEE_Result ret;
    uint32_t left_len = gp_key->data_length;
    uint32_t offset_len = 0;
    /*
     * old soft rsa key is packed with fixed sequence [e,n,d,p,q,dp,dq,qinv], d_len == 0 while crt mode,
     * otherwise no crt_mode; gp key should be packed with fixed sequence [n,e,d,p,q,dp,dq,qinv]
     */
    uint32_t fix_gp_rsa_attr[] = {
        TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT, TEE_ATTR_RSA_PRIVATE_EXPONENT,
        TEE_ATTR_RSA_PRIME1, TEE_ATTR_RSA_PRIME2, TEE_ATTR_RSA_EXPONENT1,
        TEE_ATTR_RSA_EXPONENT2, TEE_ATTR_RSA_COEFFICIENT
    };
    uint32_t index;
    uint32_t attr_len = 0;
    if (exchange_e_n_sequnce(rsa_key) != TEE_SUCCESS) {
        tloge("transfer old rsa key n, e sequence faild\n");
        return TEE_ERROR_GENERIC;
    }
    for (index = 0; index < sizeof(fix_gp_rsa_attr) / sizeof(fix_gp_rsa_attr[0]); index++) {
        ret = add_rsa_sw_one_attr(rsa_key, &offset_len, fix_gp_rsa_attr[index],
                                  gp_key->data_addr + (gp_key->data_length - left_len), &left_len, &attr_len);
        if (ret != TEE_SUCCESS) {
            tloge("rsa key sw2gp: copy attr %u fail", index);
            goto clear_key;
        }
        /* p_len, q_len, dp_len, dq_len, qinv_len value 0 with NO CRT mode, and ALL NONE-ZERO with CRT mode */
        if (attr_len == 0 && fix_gp_rsa_attr[index] == TEE_ATTR_RSA_PRIME1)
            *is_crt = GP_NOCRT_MODE;
        else
            *is_crt = GP_CRT_MODE;
    }
    tlogd("set gp crt mode %u", *is_crt);
    gp_key->data_length = gp_key->data_length - left_len;
    return ret;
clear_key:
    (void)memset_s(gp_key->data_addr, gp_key->data_length, 0, gp_key->data_length);
    return ret;
}

static TEE_Result add_rsa_dx_one_attr(uint8_t *out_buffer, uint32_t *left_len,
    uint32_t type, uint32_t *paser_len,  keymaster_blob_t *rsa_key)
{
    if (rsa_key->data_length - *paser_len < sizeof(uint32_t)) {
        tloge("add rsa one attr: key len error %u %u", rsa_key->data_length, *paser_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t len = bit_to_byte_size(*(uint32_t *)(rsa_key->data_addr + *paser_len));
    *paser_len += sizeof(uint32_t);
    if (*paser_len + len > rsa_key->data_length) {
        tloge("add rsa one attr: data len error %u, %u ,%u", *paser_len, len, rsa_key->data_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t tmp[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t)];
    TEE_Result ret = tee_ConvertLswMswWordsToMsbLsbBytes(tmp, sizeof(tmp),
                                                         (uint32_t *)(rsa_key->data_addr + *paser_len), len);
    if (ret != TEE_SUCCESS) {
        tloge("rsa dx add one: convert fail %lu %u", sizeof(tmp), len);
        return ret;
    }

    ret = add_tlv_data(out_buffer, *left_len, type, len, tmp);
    if (ret != TEE_SUCCESS) {
        tloge("rsa dx add one: add n fail");
        return ret;
    }
    *paser_len += len;
    *left_len = *left_len - KM_TLV_HEAD_LEN - len;
    return TEE_SUCCESS;
}
static TEE_Result rsa_base_key_dx2gp(keymaster_blob_t *rsa_key, uint32_t *paser_len, keymaster_blob_t *gp_key)
{
    uint32_t left_len = gp_key->data_length;
    TEE_Result ret = add_rsa_dx_one_attr(gp_key->data_addr, &left_len, TEE_ATTR_RSA_MODULUS, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa base key to gp: add n fail");
        return ret;
    }
    /* km_dx_key_rsa->crys_rsa_buff */
    *paser_len += sizeof(uint32_t) * DX_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS;
    ret = add_rsa_dx_one_attr(gp_key->data_addr + (gp_key->data_length - left_len), &left_len,
        TEE_ATTR_RSA_PUBLIC_EXPONENT, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa base key to gp: add e fail");
        return ret;
    }

    gp_key->data_length = gp_key->data_length - left_len;
    return ret;
}

static TEE_Result rsa_crt_key_dx2gp(keymaster_blob_t *rsa_key, uint32_t *paser_len, uint8_t *out_buffer,
    uint32_t total_len, uint32_t *left_len)
{
    TEE_Result ret;
    ret = add_rsa_dx_one_attr(out_buffer + total_len - *left_len, left_len,
                              TEE_ATTR_RSA_PRIME1, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa crt key to gp: add p fail");
        return ret;
    }

    ret = add_rsa_dx_one_attr(out_buffer + total_len - *left_len, left_len,
                              TEE_ATTR_RSA_PRIME2, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa crt key to gp: add q fail");
        return ret;
    }

    ret = add_rsa_dx_one_attr(out_buffer + total_len - *left_len, left_len,
                              TEE_ATTR_RSA_EXPONENT1, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa crt key to gp: add dp fail");
        return ret;
    }

    ret = add_rsa_dx_one_attr(out_buffer + total_len - *left_len, left_len,
                              TEE_ATTR_RSA_EXPONENT2, paser_len, rsa_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa crt key to gp: add dq fail");
        return ret;
    }

    ret = add_rsa_dx_one_attr(out_buffer + total_len - *left_len, left_len,
                              TEE_ATTR_RSA_COEFFICIENT, paser_len, rsa_key);
    if (ret != TEE_SUCCESS)
        tloge("rsa crt key to gp: add inv fail");

    return ret;
}

TEE_Result rsa_key_dx2gp(keymaster_blob_t *rsa_key, keymaster_blob_t *gp_key, uint32_t *is_crt)
{
    if (km_buffer_vaild(rsa_key) || km_buffer_vaild(gp_key)) {
        tloge("rsa key to gp:rsa non crt key input is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t left_len = gp_key->data_length;
    uint32_t total_len = gp_key->data_length;
    uint32_t paser_len = 0;
    TEE_Result ret = rsa_base_key_dx2gp(rsa_key, &paser_len, gp_key);
    if (ret != TEE_SUCCESS) {
        tloge("rsa key to gp:rsa key add base key fail");
        return ret;
    }
    left_len = left_len - gp_key->data_length;

    uint32_t opera_mode = *(uint32_t *)(rsa_key->data_addr + paser_len);
    /* km_dx_key_rsa:oprate mode\ key_source \ crys_pri_int_buff */
    paser_len += sizeof(opera_mode) + sizeof(uint32_t) + DX_PKA_PRI_KEY_BUFF_SIZE_IN_WORDS * sizeof(uint32_t);
    if (opera_mode == DX_RSA_NOCRT) {
        ret = add_rsa_dx_one_attr(gp_key->data_addr + total_len - left_len, &left_len,
            TEE_ATTR_RSA_PRIVATE_EXPONENT, &paser_len, rsa_key);
        *is_crt = GP_NOCRT_MODE;
    } else if (opera_mode == DX_RSA_CRT) {
        ret = rsa_crt_key_dx2gp(rsa_key, &paser_len, gp_key->data_addr, total_len, &left_len);
        *is_crt = GP_CRT_MODE;
    } else {
        tloge("rsa key to gp: unsupport operate mode %u", opera_mode);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
    if (ret != TEE_SUCCESS) {
        tloge("rsa key to gp: convert key fail");
        (void)memset_s(gp_key->data_addr, total_len, 0, total_len);
        return ret;
    }

    gp_key->data_length = total_len - left_len;
    return TEE_SUCCESS;
}

static TEE_Result ecc_pri_key_dx2gp(struct dx_ecc_pri_key *pri_key, uint32_t pri_len,
    keymaster_blob_t *gp_key, uint32_t gp_key_total_len, uint32_t *ec_cure)
{
    keymaster_blob_t gp_key_p;
    gp_key_p.data_addr = gp_key->data_addr + gp_key->data_length;
    gp_key_p.data_length = gp_key_total_len - gp_key->data_length;

    if (pri_len != sizeof(struct dx_ecc_user_pri_key)) {
        tloge("ecc pri key dx2gp: error key buffer len %u should %lu", pri_len, sizeof(struct dx_ecc_user_pri_key));
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *ec_cure = get_gp_ec_domain(pri_key->domain_id);
    uint32_t key_size_in_bites = ec_dx_domain_id_to_keysize(pri_key->domain_id);
    if (*ec_cure == KM_INVALID_VALUE || key_size_in_bites == KM_INVALID_VALUE) {
        tloge("ecc pri key dx2gp: valid dx domain %u", pri_key->domain_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t key_size_byte = bit_to_byte_size(key_size_in_bites);
    const uint32_t need_total_len = KM_TLV_HEAD_LEN + key_size_byte + KM_TLV_HEAD_LEN + sizeof(*ec_cure);
    if (need_total_len > gp_key_p.data_length) {
        tloge("ecc pri key dx to gp: short buffer need %u have %u", need_total_len, gp_key_p.data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t *temp_key = TEE_Malloc(key_size_byte, 0);
    if (temp_key == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_Result ret = tee_ConvertLswMswWordsToMsbLsbBytes(temp_key, key_size_byte, pri_key->pri_key, key_size_byte);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pri key dx to gp: convert private key fail");
        goto erase_temp_key;
    }

    ret = add_tlv_data(gp_key_p.data_addr, gp_key_p.data_length, TEE_ATTR_ECC_PRIVATE_VALUE, key_size_byte, temp_key);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pri key dx to gp: add private fail");
        goto erase_temp_key;
    }

    ret = add_tlv_data(gp_key_p.data_addr + key_size_byte + KM_TLV_HEAD_LEN,
                       gp_key_p.data_length - key_size_byte - KM_TLV_HEAD_LEN,
                       TEE_ATTR_ECC_CURVE, sizeof(*ec_cure), (uint8_t *)ec_cure);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pri key dx to gp: add curve fail");
        goto erase_temp_key;
    }
    gp_key->data_length += need_total_len;

erase_temp_key:
    (void)memset_s(temp_key, key_size_byte, 0x0, key_size_byte);
    TEE_Free(temp_key);
    return ret;
}

static TEE_Result ecc_pub_key_dx2gp(struct dx_ecc_pub_key *pub_key, uint32_t pub_len, keymaster_blob_t *gp_key,
    uint32_t *ec_cure)
{
    if (pub_len != sizeof(struct dx_ecc_user_pub_key)) {
        tloge("ecc pub key dx2gp: error key buffer len %u should %lu", pub_len, sizeof(struct dx_ecc_pub_key));
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *ec_cure = get_gp_ec_domain(pub_key->domain_id);
    uint32_t key_size_in_bites = ec_dx_domain_id_to_keysize(pub_key->domain_id);
    if (*ec_cure == KM_INVALID_VALUE || key_size_in_bites == KM_INVALID_VALUE) {
        tloge("ecc pub key dx2gp: valid dx domain %u", pub_key->domain_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t key_size_byte = bit_to_byte_size(key_size_in_bites);
    const uint32_t need_total_len = KM_TLV_HEAD_LEN + key_size_byte + KM_TLV_HEAD_LEN + key_size_byte;
    if (need_total_len > gp_key->data_length) {
        tloge("ecc pub key dx to gp: short buffer need %u have %u", need_total_len, gp_key->data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t *temp_key = TEE_Malloc(key_size_byte, 0);
    if (temp_key == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_Result ret = tee_ConvertLswMswWordsToMsbLsbBytes(temp_key, key_size_byte, pub_key->x, key_size_byte);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pub key dx to gp: convert x fail");
        goto free_temp_key;
    }

    ret = add_tlv_data(gp_key->data_addr, gp_key->data_length, TEE_ATTR_ECC_PUBLIC_VALUE_X, key_size_byte, temp_key);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pub key dx to gp: add x fail");
        goto free_temp_key;
    }

    ret = tee_ConvertLswMswWordsToMsbLsbBytes(temp_key, key_size_byte, pub_key->y, key_size_byte);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pub key dx to gp: convert y fail");
        goto free_temp_key;
    }

    ret = add_tlv_data(gp_key->data_addr + KM_TLV_HEAD_LEN + key_size_byte,
                       gp_key->data_length - KM_TLV_HEAD_LEN - key_size_byte,
                       TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_size_byte, temp_key);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pub key dx to gp: add y fail");
        goto free_temp_key;
    }

    gp_key->data_length = need_total_len;
free_temp_key:
    TEE_Free(temp_key);
    return ret;
}

TEE_Result ecc_key_dx2gp(keymaster_blob_t *pub_key, keymaster_blob_t *pri_key, uint32_t *ec_cure,
    keymaster_blob_t *gp_key)
{
    bool check_fail = ((km_buffer_vaild(pub_key) && km_buffer_vaild(pri_key)) ||
        km_buffer_vaild(gp_key) || ec_cure == NULL);
    if (check_fail) {
        tloge("ecc key dx2gp:error input");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    uint32_t gp_key_total_len = gp_key->data_length;
    if (pub_key != NULL) {
        ret = ecc_pub_key_dx2gp((struct dx_ecc_pub_key *)((struct dx_ecc_user_pub_key *)pub_key->data_addr)->pub_key,
            pub_key->data_length, gp_key, ec_cure);
        if (ret != TEE_SUCCESS) {
            tloge("ecc key dx gp: build ec pub key fail");
            return ret;
        }
    }

    if (pri_key != NULL) {
        ret = ecc_pri_key_dx2gp((struct dx_ecc_pri_key *)((struct dx_ecc_user_pri_key *)pri_key->data_addr)->pri_key,
                                pri_key->data_length, gp_key, gp_key_total_len, ec_cure);
        if (ret != TEE_SUCCESS) {
            tloge("ecc key dx gp: build ec pri key fail");
            (void)memset_s(gp_key->data_addr, gp_key_total_len, 0, gp_key_total_len);
            return ret;
        }
    }
    return ret;
}

TEE_Result symm_key_dx2gp(keymaster_blob_t *dx_key, keymaster_blob_t *gp_key)
{
    uint32_t attr_type = TEE_ATTR_SECRET_VALUE;
    uint32_t len = dx_key->data_length;
    TEE_Result ret = add_tlv_data(gp_key->data_addr, gp_key->data_length, attr_type, len, dx_key->data_addr);
    if (ret != TEE_SUCCESS)
        tloge("symm dx key to gp key fail");
    gp_key->data_length = len + KM_TLV_HEAD_LEN;
    return ret;
}

static bool rsa_use_soft(uint32_t key_size, bool digest_by_soft)
{
    uint32_t hardware_keysizes[] = { 1024, 2048, 3072 };
    uint32_t i;
    for (i = 0; i < (sizeof(hardware_keysizes) / sizeof(uint32_t)); i++)
        if (key_size == hardware_keysizes[i] && !digest_by_soft)
            return false;
    return true;
}

static TEE_Result get_params_from_keyblob(const keyblob_head *keyblob_in, uint32_t *alg, uint32_t *key_size,
    keymaster_blob_t *material, bool *digest_by_soft)
{
    uint8_t *p = (uint8_t *)keyblob_in;
    keymaster_key_param_set_t *hw_enforced = (keymaster_key_param_set_t *)(p + keyblob_in->hw_enforced_offset);
    if (get_key_param(KM_TAG_ALGORITHM, alg, hw_enforced) != 0) {
        tloge("get key param of keymaster_algorithm_t failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (get_key_param(KM_TAG_KEY_SIZE, key_size, hw_enforced) != 0) {
        if (*alg == KM_ALGORITHM_EC) {
            /* ec key size may be deduced by ec curve */
            uint32_t ec_curve_value = 0;
            if (get_key_param(KM_TAG_EC_CURVE, &ec_curve_value, hw_enforced) != 0) {
                /* must find ec curve while key size not found */
                tloge("get key param of ec_curve_value failed\n");
                return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
            }

            if (km_ec_domain_id_to_keysize((keymaster_ec_curve_t)ec_curve_value, key_size) != 0) {
                tloge("get key_size from ec_curve failed\n");
                return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
        } else {
            tloge("get key param of key size failed\n");
            return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
    }

    if (*alg == KM_ALGORITHM_RSA) {
        keymaster_digest_t digest = KM_DIGEST_MD5;
        *digest_by_soft = (is_key_param_suport(KM_TAG_DIGEST, (void *)&digest, hw_enforced) != 0);
    }
    material->data_addr = p + keyblob_in->keymaterial_offset;
    material->data_length = keyblob_in->keymaterial_size;
    return TEE_SUCCESS;
}

static TEE_Result new_rsa_material_init(keymaster_blob_t *rsa_key_material, uint32_t key_size, bool digest_by_soft,
    uint32_t total_len, struct keymaterial_rsa_header *new_key_material, keymaster_blob_t *en_key)
{
    errno_t rc;
    if (total_len < sizeof(struct keymaterial_rsa_header)) {
        tloge("init new rsa materail: short buffer %u", total_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    new_key_material->crt_mode = GP_NOCRT_MODE;
    new_key_material->key_buff_len = total_len - sizeof(struct keymaterial_rsa_header);
    if (rsa_use_soft(key_size, digest_by_soft)) {
        if (rsa_key_material->data_length < sizeof(struct soft_keymaterial_rsa)) {
            tloge("init new rsa materail: short old key material %u", rsa_key_material->data_length);
            return TEE_ERROR_SHORT_BUFFER;
        }
        struct soft_keymaterial_rsa *soft_key = (struct soft_keymaterial_rsa *)rsa_key_material->data_addr;
        en_key->data_addr = (uint8_t *)soft_key->rsa_key;
        en_key->data_length = soft_key->key_size;
        new_key_material->magic = soft_key->magic;
        rc = memcpy_s(new_key_material->iv, sizeof(new_key_material->iv), soft_key->iv, sizeof(soft_key->iv));
    } else {
        if (rsa_key_material->data_length < (sizeof(struct dx_keymaterial_rsa) - sizeof(struct km_dx_key_rsa))) {
            tloge("init new rsa materail: short old dx key material %u", rsa_key_material->data_length);
            return TEE_ERROR_SHORT_BUFFER;
        }
        struct dx_keymaterial_rsa *dx_key = (struct dx_keymaterial_rsa *)rsa_key_material->data_addr;
        en_key->data_addr = (uint8_t *)&dx_key->rsa_key;
        en_key->data_length = sizeof(struct km_dx_key_rsa);
        new_key_material->magic = dx_key->magic;
        rc = memcpy_s(new_key_material->iv, sizeof(new_key_material->iv), dx_key->iv, sizeof(dx_key->iv));
    }
    if (rc != EOK) {
        tloge("init new rsa materail: copy iv fail");
        return TEE_ERROR_SHORT_BUFFER;
    }
    return TEE_SUCCESS;
}

static TEE_Result convert_key_material_end(keymaster_blob_t *tmp_key, const keymaster_blob_t *tmp_buf_key,
    uint32_t *key_buff_len, uint32_t *data_length, uint32_t new_key_material_size)
{
    if (memcpy_s(tmp_key->data_addr, tmp_key->data_length, tmp_buf_key->data_addr, tmp_buf_key->data_length) != EOK) {
        tloge("convert symm key: copy encrypto key fail");
        return TEE_ERROR_SHORT_BUFFER;
    }
    *key_buff_len = tmp_key->data_length;
    if (*data_length < four_bytes_align_up(new_key_material_size + tmp_key->data_length)) {
        tloge("dest buffer is too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    *data_length = four_bytes_align_up(new_key_material_size + tmp_key->data_length);

    return TEE_SUCCESS;
}

static TEE_Result convert_rsa_key_material(uint32_t key_size, bool digest_by_soft, keymaster_blob_t *rsa_key_material,
    uint32_t version, const struct kb_crypto_factors *factors, keymaster_blob_t *new_material)
{
    keymaster_blob_t tmp_key;
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = {0};
    struct keymaterial_rsa_header *new_key_material = (struct keymaterial_rsa_header *)new_material->data_addr;
    TEE_Result ret = new_rsa_material_init(rsa_key_material, key_size, digest_by_soft, new_material->data_length,
        new_key_material, &tmp_key);
    if (ret != TEE_SUCCESS || tmp_key.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("convert rsa key: init new rsa key material fail or key encrypto len is error %u", tmp_key.data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    keymaster_blob_t tmp_buf_key = { temp_buf, tmp_key.data_length };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { new_key_material->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&tmp_key, &tmp_buf_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert rsa soft key: crypto rsa key fail");
        goto erase_temp_buf;
    }
    /* reinit the keyblob to another buff */
    tmp_key.data_addr = new_key_material->key;
    tmp_key.data_length = new_key_material->key_buff_len;
    if (rsa_use_soft(key_size, digest_by_soft))
        ret = rsa_key_sw2gp(&tmp_buf_key, &tmp_key, &new_key_material->crt_mode);
    else
        ret = rsa_key_dx2gp(&tmp_buf_key, &tmp_key, &new_key_material->crt_mode);
    if (ret != TEE_SUCCESS || tmp_key.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("convert rsa key: convert fail %u", tmp_key.data_length);
        goto erase_temp_buf;
    }
    tmp_buf_key.data_length = tmp_key.data_length;
    ctx.op_mode = (uint32_t)TEE_MODE_ENCRYPT;
    ret = keyblob_crypto(&tmp_key, &tmp_buf_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert rsa key: crypto rsa key fail");
        goto erase_temp_buf;
    }

    uint32_t *key_buff_len = &(new_key_material->key_buff_len);
    uint32_t *data_length = &(new_material->data_length);
    ret = convert_key_material_end(&tmp_key, &tmp_buf_key, key_buff_len, data_length, sizeof(*new_key_material));

erase_temp_buf:
    (void)memset_s(temp_buf, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

static TEE_Result new_ec_material_init(keymaster_blob_t *ec_key_material, uint32_t total_len,
    struct keymaterial_ecdsa_header *new_key_material, keymaster_blob_t *en_key)
{
    if (total_len < sizeof(struct keymaterial_ecdsa_header)) {
        tloge("init new ec materail: short buffer %u", total_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (ec_key_material->data_length < sizeof(struct dx_keymaterial_ec)) {
        tloge("init new ec materail: short old keymaterial %u", total_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    struct dx_keymaterial_ec *dx_key = (struct dx_keymaterial_ec *)ec_key_material->data_addr;
    en_key->data_addr = (uint8_t *)&dx_key->priv_key;
    en_key->data_length = sizeof(struct dx_ecc_user_pri_key);
    new_key_material->magic = dx_key->magic;
    new_key_material->key_buff_len = total_len - sizeof(struct keymaterial_ecdsa_header);
    errno_t rc = memcpy_s(new_key_material->iv, sizeof(new_key_material->iv), dx_key->iv, sizeof(dx_key->iv));
    if (rc != EOK) {
        tloge("init ec rsa materail: copy iv fail");
        return TEE_ERROR_SHORT_BUFFER;
    }
    return TEE_SUCCESS;
}

static TEE_Result convert_ecc_key_material(keymaster_blob_t *old_key_material, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *new_material)
{
    keymaster_blob_t tmp_key = { NULL, 0 };
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = { 0 };
    struct keymaterial_ecdsa_header *new_key_material = (struct keymaterial_ecdsa_header *)new_material->data_addr;
    TEE_Result ret = new_ec_material_init(old_key_material, new_material->data_length, new_key_material, &tmp_key);
    if (ret != TEE_SUCCESS || tmp_key.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("convert ec key: init new ec key material fail or key encrypto len is error %u", tmp_key.data_length);
        return ret;
    }
    keymaster_blob_t tmp_buf_key = { temp_buf, tmp_key.data_length };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { new_key_material->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&tmp_key, &tmp_buf_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert ec key: crypto ecc key fail");
        goto erase_temp_buf;
    }
    keymaster_blob_t pub_key = {
        (uint8_t *)(&((struct dx_keymaterial_ec *)old_key_material->data_addr)->pub_key),
        sizeof(struct dx_ecc_user_pub_key)
    };
    tmp_key.data_addr = temp_buf;
    tmp_buf_key.data_addr = new_key_material->key;
    tmp_buf_key.data_length = new_key_material->key_buff_len;

    ret = ecc_key_dx2gp(&pub_key, &tmp_key, &new_key_material->ecc_curv, &tmp_buf_key);
    if (ret != TEE_SUCCESS || tmp_buf_key.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("convert ecc key: convert fail %u", tmp_buf_key.data_length);
        goto erase_temp_buf;
    }
    tmp_key.data_length = tmp_buf_key.data_length;
    ctx.op_mode = (uint32_t)TEE_MODE_ENCRYPT;
    ret = keyblob_crypto(&tmp_buf_key, &tmp_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert ec key: crypto ec key fail");
        goto erase_temp_buf;
    }

    uint32_t *key_buff_len = &(new_key_material->key_buff_len);
    uint32_t *data_length = &(new_material->data_length);
    ret = convert_key_material_end(&tmp_buf_key, &tmp_key, key_buff_len, data_length, sizeof(*new_key_material));

erase_temp_buf:
    (void)memset_s(temp_buf, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

static TEE_Result convert_symm_key_material(const keymaster_blob_t *old_key_material, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *new_material)
{
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = {0};
    struct keymaterial_symmetric_header *new_key_material = NULL;
    if (old_key_material->data_length < sizeof(struct keymaterial_symmetric_header) ||
        new_material->data_length < old_key_material->data_length) {
        tloge("convert symm material: material len %u %u", old_key_material->data_length, new_material->data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (memcpy_s(new_material->data_addr, new_material->data_length, old_key_material->data_addr,
        old_key_material->data_length) != EOK) {
        tloge("convert symm material: copy fail");
        return TEE_ERROR_GENERIC;
    }
    new_key_material = (struct keymaterial_symmetric_header *)new_material->data_addr;
    keymaster_blob_t tmp_key = { new_key_material->key, new_key_material->key_buff_len };
    keymaster_blob_t tmp_buf_key = { temp_buf, new_key_material->key_buff_len };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { new_key_material->iv, IV_LEN },
        *factors
    };
    TEE_Result ret = keyblob_crypto(&tmp_key, &tmp_buf_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert symm material: crypto symm key fail");
        goto erase_temp_buf;
    }

    tmp_key.data_length = new_material->data_length - sizeof(struct keymaterial_symmetric_header);
    ret = symm_key_dx2gp(&tmp_buf_key, &tmp_key);
    if (ret != TEE_SUCCESS || tmp_key.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("convert symm material: convert fail %u", tmp_key.data_length);
        goto erase_temp_buf;
    }
    ctx.op_mode = (uint32_t)TEE_MODE_ENCRYPT;
    tmp_buf_key.data_length = tmp_key.data_length;
    ret = keyblob_crypto(&tmp_key, &tmp_buf_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("convert symm key: crypto symm key fail");
        goto erase_temp_buf;
    }

    uint32_t *key_buff_len = &(new_key_material->key_buff_len);
    uint32_t *data_length = &(new_material->data_length);
    ret = convert_key_material_end(&tmp_key, &tmp_buf_key, key_buff_len, data_length, sizeof(*new_key_material));

erase_temp_buf:
    (void)memset_s(temp_buf, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

TEE_Result build_new_key_blob(const keyblob_head *keyblob_in, const keymaster_blob_t *new_material,
    keymaster_blob_t *keyblob_out)
{
    if (keyblob_in == NULL || km_buffer_vaild(new_material) || km_buffer_vaild(keyblob_out)) {
        tloge("bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t move_len = new_material->data_length - keyblob_in->keymaterial_size;
    if (keyblob_in->keyblob_total_size > keyblob_out->data_length ||
        (int)(keyblob_out->data_length - keyblob_in->keyblob_total_size) < move_len) {
        tloge("build new key blob: short material %u %u", keyblob_in->keyblob_total_size, new_material->data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    errno_t rc = memcpy_s(keyblob_out->data_addr, keyblob_out->data_length,
                          (uint8_t *)keyblob_in, keyblob_in->keyblob_total_size);
    if (rc != EOK) {
        tloge("build new key blob: copy fail");
        return TEE_ERROR_GENERIC;
    }
    keyblob_head *new_blob = (keyblob_head *)keyblob_out->data_addr;
    new_blob->keymaterial_size = keyblob_in->keymaterial_size + move_len;
    new_blob->hw_enforced_offset = keyblob_in->hw_enforced_offset + move_len;
    new_blob->sw_enforced_offset = keyblob_in->sw_enforced_offset + move_len;
    new_blob->extend1_buf_offset = keyblob_in->extend1_buf_offset + move_len;
    new_blob->hidden_offset = keyblob_in->hidden_offset + move_len;
    new_blob->extend2_buf_offset = keyblob_in->extend2_buf_offset + move_len;
    new_blob->keyblob_total_size = keyblob_in->keyblob_total_size + move_len;
    rc = memcpy_s(keyblob_out->data_addr + new_blob->keymaterial_offset,
                  new_blob->keyblob_total_size - new_blob->keymaterial_offset,
                  new_material->data_addr, new_material->data_length);
    if (rc != EOK) {
        tloge("build new key blob: copy new material fail");
        return TEE_ERROR_GENERIC;
    }
    rc = memcpy_s(keyblob_out->data_addr + new_blob->hw_enforced_offset,
                  new_blob->keyblob_total_size - new_blob->hw_enforced_offset,
                  (uint8_t *)keyblob_in + keyblob_in->hw_enforced_offset,
                  keyblob_in->keyblob_total_size - keyblob_in->hw_enforced_offset);
    if (rc != EOK) {
        tloge("build new key blob: copy others fail");
        return TEE_ERROR_GENERIC;
    }
    keyblob_out->data_length = new_blob->keyblob_total_size;
    return TEE_SUCCESS;
}

TEE_Result get_new_key_material(const void *keyblob_in, const struct kb_crypto_factors *factors,
    keymaster_blob_t *keyblob_out)
{
    if (keyblob_in == NULL || km_buffer_vaild(keyblob_out)) {
        tloge("new key material: input is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t alg;
    uint32_t key_size;
    keymaster_blob_t dx_key_mate;
    keymaster_blob_t new_material;
    bool rsa_digest_by_soft = false;
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = {0};
    TEE_Result ret = get_params_from_keyblob((keyblob_head *)keyblob_in, &alg, &key_size, &dx_key_mate,
        &rsa_digest_by_soft);
    if (ret != TEE_SUCCESS) {
        tloge("new key material: init fail");
        return ret;
    }
    new_material.data_addr = temp_buf;
    new_material.data_length = MAX_KEY_BUFFER_LEN;
    switch (alg) {
    case KM_ALGORITHM_RSA:
        ret = convert_rsa_key_material(key_size, rsa_digest_by_soft, &dx_key_mate,
            ((keyblob_head *)keyblob_in)->version, factors, &new_material);
        break;
    case KM_ALGORITHM_EC:
        ret = convert_ecc_key_material(&dx_key_mate, ((keyblob_head *)keyblob_in)->version, factors,
            &new_material);
        break;
    case KM_ALGORITHM_AES:
    case KM_ALGORITHM_HMAC:
    case KM_ALGORITHM_TRIPLE_DES:
        ret = convert_symm_key_material(&dx_key_mate, ((keyblob_head *)keyblob_in)->version, factors,
            &new_material);
        break;
    default:
        tloge("new key material:unspport alg type %u", alg);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ret != TEE_SUCCESS) {
        tloge("new key material: convert fail");
        (void)memset_s(temp_buf, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
        return ret;
    }
    ret = build_new_key_blob(keyblob_in, &new_material, keyblob_out);
    (void)memset_s(temp_buf, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}
