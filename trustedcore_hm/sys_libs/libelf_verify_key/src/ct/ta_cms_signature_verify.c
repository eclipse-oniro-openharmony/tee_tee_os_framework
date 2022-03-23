/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: verify cms signature in ct.
 * Author: hemuyang1@huawei.com
 * Create: 2021-06-10
 */
#include "ta_cms_signature_verify.h"
#include "tee_log.h"

#define TLV_HEAD_OFFSET (2 * sizeof(uint32_t))
#define CMS_SIGNATURE_HEAD_MIN (3 * TLV_HEAD_OFFSET)

TEE_Result ta_cms_signature_verify(uint8_t *signature, uint32_t signature_size, uint8_t *hash, uint32_t hash_size)
{
    struct cms_sign_info cms_sign = {0};
    uint32_t offset;
    uint32_t tag;
    bool check = (signature == NULL || signature_size <= CMS_SIGNATURE_HEAD_MIN || hash == NULL || hash_size == 0);
    if (check) {
        tloge("signature or hash is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset = TLV_HEAD_OFFSET;
    tag = *(uint32_t *)(signature + offset);
    if (tag != CMS_SIGNATURE_CRL_TAG) {
        tloge("crl tag is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset += sizeof(tag);
    cms_sign.crl_len = *(uint32_t *)(signature + offset);
    if (cms_sign.crl_len >= signature_size - CMS_SIGNATURE_HEAD_MIN) {
        tloge("crl length is too long, %u\n", cms_sign.crl_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset += sizeof(cms_sign.crl_len);
    cms_sign.crl_buf = signature + offset;

    offset += cms_sign.crl_len;
    tag = *(uint32_t *)(signature + offset);
    if (tag != CMS_SIGNATURE_CMS_TAG) {
        tloge("cms tag is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset += sizeof(tag);
    cms_sign.cms_len = *(uint32_t *)(signature + offset);
    if (cms_sign.cms_len != signature_size - CMS_SIGNATURE_HEAD_MIN - cms_sign.crl_len) {
        tloge("crl length is invalid, %u\n", cms_sign.cms_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset += sizeof(cms_sign.cms_len);
    cms_sign.cms_buf = signature + offset;

    cms_sign.ini_buf = hash;
    cms_sign.ini_len = hash_size;

    return check_cms_signature(&cms_sign);
}
