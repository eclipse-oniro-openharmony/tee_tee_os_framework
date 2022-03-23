/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for deriving HUK
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */
#ifndef HWAA_KHARDWARE_H
#define HWAA_KHARDWARE_H

#include "securec.h"
#include "tee_internal_api.h"

#define HWAA_KEY_SEED_KEY_LEN 32
#define SALT_SIZE 16

/*
 *   This function reads device-specific bits that can be used as the key seed.
 *   @param outBytes             [out] Destination of device-specific bits
 *   @param outBytesSize         [out] number of bytes read
 *   @return 0 if successful
 */
TEE_Result ReadTeeDeviceUniqueBytes(uint8_t **outBytes, uint32_t *outBytesSize);

#endif
