/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: add aes-ccm alg for kds TA
 * Create: 2019-01-31
 */
#include "tee_crypto_kds_api.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_api.h>

#define AE_MAX_TAG_LEN 16
TEE_Result TEE_AEEncryptFinal_KDS(TEE_OperationHandle operation, void *src_data, size_t src_len, void *dest_data,
                                  size_t *dest_len, size_t *tag_len)
{
    bool check = (src_data == NULL || src_len == 0 || dest_data == NULL || dest_len == NULL || *dest_len == 0 ||
        tag_len == NULL || *dest_len < src_len || operation == NULL);
    if (check) {
        tloge("Dest len or tag len is null!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t init_dest_len      = *dest_len;
    size_t size_of_tag          = AE_MAX_TAG_LEN;
    uint8_t tag[AE_MAX_TAG_LEN] = { 0 };

    TEE_Result ret = TEE_AEEncryptFinal(operation, src_data, src_len, dest_data, dest_len, tag, &size_of_tag);
    if (ret != TEE_SUCCESS) {
        tloge("Tee ae encrypt final failed, ret = 0x%x\n", ret);
        return ret;
    }

    if (*tag_len < size_of_tag) {
        tloge("tag_len 0x%x small than real 0x%x\n", *tag_len, size_of_tag);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((init_dest_len - src_len) < size_of_tag) {
        tloge("Dest_len 0x%x small than real len 0x%x\n", init_dest_len, (src_len + size_of_tag));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    errno_t rc = memcpy_s(dest_data + src_len, init_dest_len - src_len, tag, size_of_tag);
    (void)memset_s(tag, AE_MAX_TAG_LEN, 0, AE_MAX_TAG_LEN);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }

    *tag_len                = size_of_tag;
    *dest_len               = src_len + size_of_tag;

    tlogd("Tee ae encrypt final for kds ok\n");
    return ret;
}

TEE_Result TEE_AEDecryptFinal_KDS(TEE_OperationHandle operation, void *src_data, size_t src_len, void *dest_data,
                                  size_t *dest_len, size_t tag_len)
{
    bool is_abnormal = ((src_data == NULL) || (dest_data == NULL) || (dest_len == NULL) || (*dest_len == 0) ||
        (tag_len == 0) || (src_len < tag_len) || (tag_len > AE_MAX_TAG_LEN) || (operation == NULL));
    if (is_abnormal) {
        tloge("Input params is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t data_in_size       = src_len - tag_len;
    uint8_t tag[AE_MAX_TAG_LEN] = { 0 };
    errno_t rc                  = memcpy_s(tag, sizeof(tag), src_data + (src_len - tag_len), tag_len);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }

    TEE_Result ret = TEE_AEDecryptFinal(operation, src_data, data_in_size, dest_data, dest_len, tag, tag_len);
    (void)memset_s(tag, AE_MAX_TAG_LEN, 0, AE_MAX_TAG_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("Tee ae decrypt final failed, ret = 0x%x\n", ret);
        return ret;
    }

    tlogd("Tee ae decrypt final for kds ok\n");
    return TEE_SUCCESS;
}
