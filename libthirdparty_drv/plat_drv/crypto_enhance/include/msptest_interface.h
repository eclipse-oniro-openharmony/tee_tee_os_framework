/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Call interface for TA
 * Author: zhaohaisheng z00452790
 * Create: 2018-12-01
 */

#ifndef __HIEPS_INTERFACE_H__
#define __HIEPS_INTERFACE_H__

#include <eps_ddr_layout_define.h>
#include <soc_acpu_baseaddr_interface.h>

#define HIEPS_BASE_DDR            (HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_LCS_ADDR            (EPS_LCS_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))

#ifdef CONFIG_HIEPS_BYPASS_LITE_CHIP
#define HIEPS_EFUSE_LITE_FLAG_MASK     0x1
#define HIEPS_EFUSE_MODEM_FLAG_MASK    0x2

/* cs2 lite chip flag */
enum {
    IS_NORMAL_CHIP_FLAG = 0, /* normal chip */
    IS_LITE_CHIP_FLAG   = 1, /* lite chip */
};

/* modem bypass flag */
enum {
    MODEM_NOT_BYPASS_FLAG = 0, /* modem not bypass */
    MODEM_BYPASS_FLAG     = 1, /* modem bypass */
};
#endif

uint32_t tee_call_hieps_drivers(uint32_t cmd, char *input,
	uint32_t max_input_len, const char *parm_info, uint32_t parm_size);

#endif /* __HIEPS_INTERFACE_H__ */
