/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: policy definitions
 * Create: 2020-09-10
 */

#include "tee_ta_load.h"

int32_t is_third_identity(uint8_t *buffer, uint32_t size)
{
    (void)buffer;
    (void)size;
    return false;
}

TEE_Result process_header_third(uint8_t *buffer, uint32_t size, teec_image_info *img_info)
{
    (void)buffer;
    (void)size;
    (void)img_info;
    return TEE_ERROR_GENERIC;
}

TEE_Result process_body_third(uint8_t *buffer, uint32_t size, teec_image_info *img_info)
{
    (void)buffer;
    (void)size;
    (void)img_info;
    return TEE_ERROR_GENERIC;
}

void process_end_third(void)
{
    return;
}
