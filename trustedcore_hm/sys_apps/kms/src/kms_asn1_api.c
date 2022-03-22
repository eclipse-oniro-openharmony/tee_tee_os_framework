/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:KMS ASN1 function
 * Create: 2021-08-10
 */

#include "kms_pub_def.h"
#include "kms_asn1_api.h"
#include "securec.h"
#include "tee_log.h"
#include "crypto_wrapper.h"

/* 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type) */
const uint8_t oid_ecpublickey[7] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
/* 1.2.156.10197.1.301 sm2ECC (China GM Standards Committee) */
const uint8_t oid_sm2ecc[8] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D};
#define LENGTH_LEN_ONE_BYTE 0x81
#define LENGTH_LEN_TWO_BYTE 0x82

static TEE_Result der_encode(uint8_t tag, uint32_t length, const uint8_t *value, uint8_t *der_data, uint32_t *data_len)
{
    uint32_t pad = 0;
    uint32_t index = 0;
    uint32_t total_len = *data_len;
    uint8_t header[MAX_HEADER_LEN] = { 0 };
    header[index++] = tag;
    /* If we have bit string, we need to put unused bits */
    if ((TAG_BITSTRING == tag) || ((TAG_INTEGER == tag) && (value[0] > 0x7f))) {
        pad++;
        length++;
    }
    if (length <= 0x7F) {
        header[index++] = length;
    } else if (length <= 0xFF) {
        header[index++] = LENGTH_LEN_ONE_BYTE;
        header[index++] = length;
    } else {
        header[index++] = LENGTH_LEN_TWO_BYTE;
        header[index++] = (length >> RIGHT_SHIFT_ONE_BYTE) & 0xFF;
        header[index++] = length & 0xFF;
    }
    if (pad > 0)
        header[index++] = 0;
    if (total_len < index) {
        tloge("der encode failed : buffer short\n ");
        return TEE_ERROR_SHORT_BUFFER;
    }
    errno_t rc = memmove_s(der_data + index, total_len - index, value, length - pad);
    if (rc != EOK) {
        tloge("der encode fail : memory move\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    rc = memcpy_s(der_data, total_len, header, index);
    if (rc != EOK) {
        tloge("der encode fail : add header\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    *data_len = index + length - pad;
    return TEE_SUCCESS;
}

static TEE_Result ecc_get_algid(uint8_t *data, uint32_t *data_len, const uint8_t *name_curve, uint32_t name_len)
{
    uint32_t len = *data_len;
    const uint8_t *oid_ecpubkey = oid_ecpublickey;
    uint32_t oid_ecpubkey_len = sizeof(oid_ecpublickey);
    TEE_Result ret = der_encode(TAG_OID, oid_ecpubkey_len, oid_ecpubkey, data, &len);
    if (ret != TEE_SUCCESS)
        return ret;
    uint32_t offset = len;
    if (*data_len < offset) {
        tloge("ecc get algid: buffer too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    len = *data_len - offset;
    ret = der_encode(TAG_OID, name_len, name_curve, data + offset, &len);
    if (ret != TEE_SUCCESS)
        return ret;
    offset += len;
    return der_encode(TAG_SEQUENCE, offset, data, data, data_len);
}

static TEE_Result pubkey_integer_to_string(uint8_t *buffer, uint32_t *buffer_len,
    const uint8_t *data, uint32_t data_len, uint32_t mode_len)
{
    uint32_t len = *buffer_len;
    if (len < mode_len) {
        tloge("pubkey to bit string:buffer too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    errno_t rc = memset_s(buffer, len, 0, len);
    if (rc != EOK) {
        tloge("pubkey to bit string:memset failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (data_len >= mode_len)
        rc = memcpy_s(buffer, len, data + data_len - mode_len, mode_len);
    else
        rc = memcpy_s(buffer + mode_len - data_len, len + data_len - mode_len, data, data_len);
    if (rc != EOK) {
        tloge("pubkey to bit string:memcpy_s fail\n");
        return TEE_ERROR_GENERIC;
    }
    *buffer_len = mode_len;
    return TEE_SUCCESS;
}

static TEE_Result ecc_get_pubkey_sub(uint8_t *data, uint32_t *data_len, const ecc_pub_key_t *ecc_pub_key,
    uint32_t mode_len)
{
    if (mode_len < ecc_pub_key->x_len || mode_len < ecc_pub_key->y_len) {
        tloge("get pubkey subject fail: params error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t offset = 0;
    data[offset++] = ECPOINT;
    if (*data_len < offset) {
        tloge("get pubkey sub buffer short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    uint32_t bitstring_len = *data_len - offset;
    TEE_Result ret = pubkey_integer_to_string(data + offset, &bitstring_len,
        ecc_pub_key->x, ecc_pub_key->x_len, mode_len);
    if (ret != TEE_SUCCESS) {
        tloge("get pubkey subject fail: get x\n");
        return ret;
    }
    offset += bitstring_len;
    bitstring_len = *data_len - offset;
    ret = pubkey_integer_to_string(data + offset, &bitstring_len, ecc_pub_key->y, ecc_pub_key->y_len, mode_len);
    if (ret != TEE_SUCCESS) {
        tloge("get pubkey subject fail: get y\n");
        return ret;
    }
    offset += bitstring_len;
    return der_encode(TAG_BITSTRING, offset, data, data, data_len);
}

TEE_Result ecc_pubkey_to_asn1(struct kms_buffer_data *in_pub_key, struct kms_buffer_data *out_pub_key)
{
    uint8_t encode_pubkey[MAX_PUBKEY_LEN] = { 0 };
    const uint8_t *name_curve;
    uint32_t name_len;
    uint32_t mode_len;
    bool check = ((in_pub_key == NULL) || (in_pub_key->buffer == NULL) || (out_pub_key == NULL) ||
        (out_pub_key->buffer == NULL) || (in_pub_key->length < sizeof(ecc_pub_key_t)));
    if (check) {
        tloge("ecc pubkey to asn1 : params error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_pub_key_t *ecc_pub_key = (ecc_pub_key_t *)(in_pub_key->buffer);
    switch (ecc_pub_key->domain) {
    case TEE_ECC_CURVE_SM2:
        name_curve = oid_sm2ecc;
        name_len = sizeof(oid_sm2ecc);
        mode_len = SM2_MODE_LEN;
        break;
    default:
        tloge("unspport algorithm\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t algid_len = MAX_PUBKEY_LEN;
    TEE_Result ret = ecc_get_algid(encode_pubkey, &algid_len, name_curve, name_len);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pubkey to asn1: get algid error\n");
        return ret;
    }
    uint32_t pubkey_subject_len = MAX_PUBKEY_LEN - algid_len;
    ret = ecc_get_pubkey_sub(encode_pubkey + algid_len, &pubkey_subject_len, ecc_pub_key, mode_len);
    if (ret != TEE_SUCCESS) {
        tloge("ecc pubkey to asn1: get pubkey subject error\n");
        return ret;
    }
    return der_encode(TAG_SEQUENCE, algid_len + pubkey_subject_len, encode_pubkey,
                      out_pub_key->buffer, &out_pub_key->length);
}

