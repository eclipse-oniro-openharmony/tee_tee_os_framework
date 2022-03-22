/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Call interface for TA
 * Create: 2018-12-01
 */

#ifndef __HIEPS_INTERFACE_H__
#define __HIEPS_INTERFACE_H__

#include <eps_ddr_layout_define.h>
#include <soc_acpu_baseaddr_interface.h>

#define HIEPS_BASE_DDR            (HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_LCS_ADDR            (EPS_LCS_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))

uint32_t tee_call_hieps_drivers(uint32_t cmd, char *input,
	uint32_t max_input_len, const char *parm_info, uint32_t parm_size);

#endif /* __HIEPS_INTERFACE_H__ */
