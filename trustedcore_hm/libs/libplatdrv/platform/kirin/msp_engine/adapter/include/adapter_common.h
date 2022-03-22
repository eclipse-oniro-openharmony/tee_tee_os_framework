/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter common interface
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_COMMON_H__
#define __ADAPTER_COMMON_H__

#include <crypto_driver_adaptor.h>
#include <pal_types.h>

#define PARAM_NUM_MAX           3

enum adapter_algo_type {
	ADAPTER_ALGO_HASH = 0x90000001,
	ADAPTER_ALGO_HMAC,
};

err_bsp_t adapter_symm_algo_convert(uint32_t adapter_algo, u32 *palgo_type, u32 *palgo_mode);

err_bsp_t adapter_asymm_algo_convert(uint32_t adapter_algo, u32 *palgo_type);

#endif

