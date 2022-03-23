/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for msp core extend api.
 * Author : w00371137
 * Create: 2020/02/29
 */

#ifndef __MSPC_HW_STATUS_H__
#define __MSPC_HW_STATUS_H__

#include <stdint.h>
#include <tee_internal_api.h>

#define MSP_HW_AVAILABLE            0x55
#define MSP_HW_UNAVAILABLE          0xAA

#define MSP_SERVICE_IS_SUPPORTED    0x5A
#define MSP_SERVICE_NOT_SUPPORTED   0xA5

TEE_Result mspcore_get_hw_status(uint32_t *status);
TEE_Result mspcore_get_service_status(uint32_t service_id, uint8_t *status);

#endif
