/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-06
 * Description: tee crypto definitions
 */

#ifndef TEE_CRYPTO_COMMON_HASH_H
#define TEE_CRYPTO_COMMON_HASH_H

#include "tee_crypto_api.h"
TEE_Result digest_operation_state_check(const TEE_OperationHandle operation);
TEE_Result proc_hal_digest_init(TEE_OperationHandle operation);
TEE_Result proc_hal_digest_update(TEE_OperationHandle operation, const void *chunk, size_t chunk_size);
#endif

