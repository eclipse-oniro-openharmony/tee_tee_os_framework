/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: dft for rng factory test
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/04/18
 */
#ifndef __HAL_TRNG_BM_H__
#define __HAL_TRNG_BM_H__
#include <pal_errno.h>

/**
 * @brief      : hal_trng_bm
 * @param[in]  : void
 * @return     : ::err_bsp_t
 * @note       :rng bm test
 */
err_bsp_t hal_trng_bm(void);

err_bsp_t hal_trng_v2_bm(void);

#endif
