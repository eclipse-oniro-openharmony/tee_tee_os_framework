/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: delaration for selftest
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/08/09
 */
#ifndef __HAL_SCE_SELFTEST_H__
#define __HAL_SCE_SELFTEST_H__
#include <pal_types.h>
#include <hal_cipher.h>

err_bsp_t hal_aes_selftest(u32 strategy);
err_bsp_t hal_des_selftest(void);
err_bsp_t hal_tdes_selftest(void);
err_bsp_t hal_sm4_selftest(void);
err_bsp_t hal_sha1_selftest(void);
err_bsp_t hal_sha256_selftest(void);
err_bsp_t hal_sm3_selftest(void);

err_bsp_t hal_symm_selftest(void);

#endif
