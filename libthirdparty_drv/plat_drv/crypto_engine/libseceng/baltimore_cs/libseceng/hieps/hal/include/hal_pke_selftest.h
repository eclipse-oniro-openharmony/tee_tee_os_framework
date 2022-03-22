/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: PKE selftest
 * Author     : h00401342
 * Create     : 2019/08/19
 * Note       :
 */
#ifndef __HAL_PKE_SELFTEST_H__
#define __HAL_PKE_SELFTEST_H__
#include <pal_types.h>

/**
 * @brief      : rsa ip mod me selftest
 */
err_bsp_t hal_rsa_selftest(void);

/**
 * @brief      : ecc paddselftest
 */
err_bsp_t hal_ecc_paddselftest(void);

/**
 * @brief      : ecc pmulselftest
 */
err_bsp_t hal_ecc_pmulselftest(void);

err_bsp_t hal_sm9_selftest(void);

#endif /* end of __HAL_PKE_SELFTEST_H__ */
