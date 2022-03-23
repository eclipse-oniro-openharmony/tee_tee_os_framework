/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the definition required for Initialiazation and Destroy
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#ifndef HWAA_KINITIALIZE_H
#define HWAA_KINITIALIZE_H

#include "securec.h"
#include "tee_internal_api.h"

/*
 *   This function initializes key seed for post-quantum algorithm and must be called
 *   immediately after tee application is loaded.
 *   @return 0 if successful
 */
TEE_Result InitializeTee(void);

/* Invoke the TEE interface to get the key seed */
TEE_Result GetKeySeed(uint8_t **keySeed, uint32_t *keySize);

/*
 *   This function deallocates global dynamic memory allocated when tee application is running and
 *   should be called immediately before tee application is unloaded.
 */
void DestroyTee(void);

#endif