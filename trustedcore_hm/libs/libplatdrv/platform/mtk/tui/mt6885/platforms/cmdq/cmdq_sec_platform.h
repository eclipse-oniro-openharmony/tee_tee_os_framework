/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __CMDQ_SEC_PLATFORM_H__
#define __CMDQ_SEC_PLATFORM_H__

/* platform dependent utilities, format: cmdq_{util_type}_{name} */

#include "cmdq_sec_def.h"
#include "cmdq_sec_core.h"

#define CMDQ_SPECIAL_SUBSYS_ADDR 99

void cmdq_tz_poke_notify_loop(void);

bool cmdq_tz_is_a_secure_thread(const int32_t thread);

/*
 * GCE capability
 */

/* get LSB for subsys encoding in argA (range: 0 - 31) */
uint32_t cmdq_tz_get_subsys_LSB_in_argA(void);
/* get subsys from physical address */
int32_t cmdq_tz_subsys_from_phys_addr(uint32_t physAddr);

/* scenario */
bool cmdq_tz_is_disp_scenario(const CMDQ_SCENARIO_ENUM scenario);
CMDQ_HW_THREAD_PRIORITY_ENUM cmdq_tz_priority_from_scenario(CMDQ_SCENARIO_ENUM scenario);
int cmdq_tz_thread_index_from_scenario(CMDQ_SCENARIO_ENUM scenario);

/**
 * Record usage
 *
 */
uint64_t cmdq_tz_rec_flag_from_scenario(CMDQ_SCENARIO_ENUM scn);
bool cmdq_tz_should_enable_prefetch(CMDQ_SCENARIO_ENUM scenario);

/**
 * Debug
 *
 */
void cmdq_tz_dump_mmsys_config(void);

/**
 * Security
 */
int32_t cmdq_tz_get_DAPC_security_reg_and_mask(
			const CMDQ_SCENARIO_ENUM scenario,
			uint64_t engineFlag,
			uint32_t *pInstrA, uint32_t *pInstrB, uint32_t *pValueEnabled, uint32_t *pValueDisabled);
int32_t cmdq_tz_get_port_security_reg_and_mask(
			uint64_t engineFlag, uint32_t *pInstrA, uint32_t *pInstrB, uint32_t *pValueEnabled, uint32_t *pValueDisabled);

#endif				/* __CMDQ_SEC_PLATFORM_H__ */
