/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: add aes-ccm alg for kds TA
 * Create: 2019-01-31
 */
#ifndef TEE_CRYPTO_KDS_API_H
#define TEE_CRYPTO_KDS_API_H

#include <tee_defines.h>

TEE_Result TEE_AEEncryptFinal_KDS(TEE_OperationHandle operation, void *src_data, size_t src_len, void *dest_data,
                                  size_t *dest_len, size_t *tag_len);
TEE_Result TEE_AEDecryptFinal_KDS(TEE_OperationHandle operation, void *src_data, size_t src_len, void *dest_data,
                                  size_t *dest_len, size_t tag_len);
#endif
