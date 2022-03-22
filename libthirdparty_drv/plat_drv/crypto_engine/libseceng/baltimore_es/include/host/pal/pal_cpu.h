/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: pal function interface for cpu
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/15
 */
#ifndef __PAL_CPU_H__
#define __PAL_CPU_H__
#include <common_define.h>
#include <pal_cpu_plat.h>

#ifndef PAL_ISFPGA
#define PAL_ISFPGA        0
#endif /* PAL_ISFPGA */

#ifndef PAL_PM_POWER_CONFIG
#define PAL_PM_POWER_CONFIG(mid, ip_idx, onoff) BSP_RET_OK
#endif /* PAL_PM_POWER_CONFIG */

#ifndef PAL_ASM_NOP
#define PAL_ASM_NOP() OBJECT(asm volatile ("nop"))
#endif /* PAL_ASM_NOP */

/**
 * @brief      : convert cpu addr to master addr
 * @param[out] : master_addr pointer to pal_master_addr_t
 */
err_bsp_t pal_convert_addr_cpu2master(
	const pal_cpu_addr_t cpu_addr, pal_master_addr_t *master_addr);

/**
 * @brief      : convert master addr to cpu addr
 * @param[in]  : master_addr
 * @param[out] : cpu_addr
 * @return     : error code
 */

err_bsp_t pal_convert_addr_master2cpu(
	const pal_master_addr_t master_addr, pal_cpu_addr_t *cpu_addr);

/**
 * @brief      : get eng working frequency
 * @return     : frequency (M)
 */
u32 pal_get_eng_frequency(void);

/**
 * @brief      : mmu enable
 */
err_bsp_t pal_mmu_enable(u32 ip_idx, u32 read_en, u32 write_en, u32 is_sec);

/**
 * @brief      : mmu disable
 */
err_bsp_t pal_mmu_disable(u32 ip_idx, u32 is_sec);

#endif /* __PAL_CPU_H__ */
