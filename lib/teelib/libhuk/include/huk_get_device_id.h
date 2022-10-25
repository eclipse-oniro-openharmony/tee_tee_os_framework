/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk get device id
 * Create: 2022-10-25
 */
#ifndef HUK_GET_DEVICE_ID_H
#define HUK_GET_DEVICE_ID_H

#include <tee_defines.h>

TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len);

#endif