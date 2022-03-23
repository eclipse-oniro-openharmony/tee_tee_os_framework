/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: design for test
 * Author     : m00475438
 * Create     : 2018/08/13
 */
#ifndef __PAL_DFT_H__
#define __PAL_DFT_H__
#include <pal_types.h>
#include <pal_dft_plat.h>

/**
 * @brief      : disable seceng system reset
 * @param[in]  : pstat seceng system reset status pointer
 */
void pal_sysrst_save(u32 *pstat);

/**
 * @brief      : restore seceng system reset status
 * @param[in]  : stat seceng system reset status
 */
void pal_sysrst_restore(u32 stat);

#endif /* __PAL_DFT_H__ */
