/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-01
 * Description: soft device key engine
 */
#ifndef __CRYPTO_DEVICE_KEY_WRAPPER_H__
#define __CRYPTO_DEVICE_KEY_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>

/*
 * Get oem huk.
 *
 * @param huk      [OUT] The oem huk buffer
 * @param key      [IN]  The hmac key buffer
 * @param key_size [IN]  The length of hmac key buffer
 *
 * @return  0: Get oem huk success
 * @return -1: Get oem huk failed
 */
int32_t get_class_oem_huk(uint8_t *huk, const uint8_t *key, uint32_t key_size);

#endif
