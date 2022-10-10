/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee operation valid implemetion
 * Create: 2019-10-11
 */

#ifndef SRC_TEE_TEE_OPERATION_H
#define SRC_TEE_TEE_OPERATION_H

#include "tee_crypto_api.h"

TEE_Result add_operation(TEE_OperationHandle operation);
void delete_operation(const TEE_OperationHandle operation);
TEE_Result check_operation(const TEE_OperationHandle operation);

#endif
