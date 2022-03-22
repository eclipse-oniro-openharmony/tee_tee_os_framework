/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM counter api function and algorithm check head
 * Author: chenyao
 * Create: 2020-01-08
 */
#ifndef _HSM_COUNT_API_H_
#define _HSM_COUNT_API_H_

#include "hsm_public.h"

#define HSM_AC_STATUS_CHECK_LEN     0x4

typedef struct {
    uint8_t             *counter_info;
    uint8_t             *counter_auth;
    uint32_t            counter_auth_len;
    uint32_t            *counter_id;
} HSM_COUNT_CREATE_INFO;

typedef struct {
    uint8_t             *counter_info;
    uint32_t            counter_id;
    uint64_t            *count_value;
} HSM_COUNT_READ_INFO;

typedef struct {
    uint8_t             *counter_info;
    uint32_t            counter_id;
    uint8_t             *counter_auth;
    uint32_t            counter_auth_len;
} HSM_COUNT_DELETE_INFO;

typedef struct {
    uint8_t             *counter_info;
    uint32_t            counter_id;
    uint8_t             *counter_auth;
    uint32_t            counter_auth_len;
    uint64_t            counter_value_add;
    uint64_t            *counter_value;
} HSM_COUNT_INC_INFO;

TEE_Result TEE_HSM_CounterInit(uint32_t dev_id, uint8_t *counter_info);
TEE_Result TEE_HSM_CounterCreate(uint32_t dev_id, HSM_COUNT_CREATE_INFO *hsm_count_create_info);
TEE_Result TEE_HSM_CounterRead(uint32_t dev_id, HSM_COUNT_READ_INFO *hsm_count_read_info);
TEE_Result TEE_HSM_CounterDelete(uint32_t dev_id, HSM_COUNT_DELETE_INFO *hsm_count_delete_info);
TEE_Result TEE_HSM_CounterInc(uint32_t dev_id, HSM_COUNT_INC_INFO *hsm_count_inc_info);
TEE_Result TEE_HSM_AlgCheck(uint32_t dev_id, uint32_t *hsm_accelerator_status, uint32_t hsm_status_len);

#endif
