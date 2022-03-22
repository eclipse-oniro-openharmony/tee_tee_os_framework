/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: random number generator functions for hardware
 * Author     : h00418764
 * Create     : 2018/02/24
 */
#ifndef __HAL_TRNG_H__
#define __HAL_TRNG_H__
#include <common_define.h>

err_bsp_t hal_trng_init(void);

err_bsp_t hal_trng_selftest(void);

/**
 * @brief      : read one word random num from hardware
 * @param[out] : ptrnd one word trnd
 * @note       : data is valid only when trng is ready
 */
err_bsp_t hal_trng_read_one(u32 *ptrnd);

/**
 * @brief      : rng_gen_trnd
 *               gen true(hardware) random num and write to user's buffer
 * @param[out] : ptrnd, pointer to user's buffer
 * @param[in]  : len, byte length of buffer
 */
err_bsp_t hal_trng_generate(u8 *ptrnd, u32 len);

#endif /* end of __HAL_TRNG_H__ */
