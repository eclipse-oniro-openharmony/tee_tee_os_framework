/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dft for ECC test
 * Author     : security-engine
 * Create     : 2020/05/16
 */
#ifndef __HAL_ECC_DFT_H__
#define __HAL_ECC_DFT_H__
#include <pal_types.h>
#include <pal_errno.h>

err_bsp_t hal_ecc_set_random_indomain(u8 *r, u32 r_len);

#endif /* end of __HAL_ECC_DFT_H__ */

