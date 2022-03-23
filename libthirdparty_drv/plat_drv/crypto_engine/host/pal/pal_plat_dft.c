/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: design for test
 * Author     : m00475438
 * Create     : 2018/08/20
 */
#include <pal_dft.h>
#include <pal_log.h>
#include <pal_cpu.h>
#include <common_utils.h>
#include <hat_memory.h>

#define BSP_THIS_MODULE                           BSP_MODULE_SYS

/**
 * @brief      : disable seceng system reset
 * @param[in]  : pstat seceng system reset status pointer
 * @return     : void
 */
void pal_sysrst_save(u32 *pstat)
{
	UNUSED(pstat);
}

/**
 * @brief      : restore seceng system reset status
 * @param[in]  : stat seceng system reset status
 * @return     : void
 */
void pal_sysrst_restore(u32 stat)
{
	UNUSED(stat);
}

