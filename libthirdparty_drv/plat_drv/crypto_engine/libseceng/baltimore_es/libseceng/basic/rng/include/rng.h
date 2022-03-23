/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: random number generator functions
 * Author     : m00475438
 * Create     : 2019/08/05
 */

#ifndef __RNG_H__
#define __RNG_H__
#include <common_define.h>

err_bsp_t rng_initialize(void);

/**
 * @brief      : generate true(hardware) random numbers data
 * @param[out] : ptrnd output buffer for trnd
 * @param[in]  : len   buffer bytes length
 */
err_bsp_t rng_gen_trnd(u8 *ptrnd, u32 len);

/**
 * @brief      : generate pseudo-random(software) numbers data
 * @param[out] : pprnd output buffer for prnd
 * @param[in]  : len   buffer bytes length
 */
err_bsp_t rng_gen_prnd(u8 *pprnd, u32 len);

#endif /* end of __RNG_H__ */
