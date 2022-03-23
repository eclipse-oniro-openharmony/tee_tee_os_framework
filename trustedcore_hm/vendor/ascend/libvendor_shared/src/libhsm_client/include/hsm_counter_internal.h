/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: HSM kms internal function head
 * Author: chenyao
 * Create: 2019-01-08
 */
#ifndef _HSM_COUNT_INTERNAL_H_
#define _HSM_COUNT_INTERNAL_H_

#include "hsm_public.h"
#include "hsm_counter_api.h"

TEE_Result counter_create_para_check(HSM_COUNT_CREATE_INFO *hsm_count_create_info);
TEE_Result counter_create_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_CREATE_INFO *hsm_count_create_info);
TEE_Result counter_read_para_check(HSM_COUNT_READ_INFO *hsm_count_read_info);
TEE_Result counter_read_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_READ_INFO *hsm_count_read_info);
TEE_Result counter_delete_para_check(HSM_COUNT_DELETE_INFO *hsm_count_delete_info);
TEE_Result counter_delete_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_DELETE_INFO *hsm_count_delete_info);
TEE_Result counter_inc_para_check(HSM_COUNT_INC_INFO *hsm_count_inc_info);
TEE_Result counter_inc_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_INC_INFO *hsm_count_inc_info);

#endif
