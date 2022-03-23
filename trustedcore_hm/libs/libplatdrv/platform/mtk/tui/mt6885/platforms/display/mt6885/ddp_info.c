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

#define LOG_TAG "INFO"
#include"ddp_info.h"
#include"ddp_debug.h"
#include "ddp_log.h"

#define DDP_MODULE_REG_RANGE	(0x1000)

static const char reg_magic[] = "no_regs_info";


struct ddp_module ddp_modules[DISP_MODULE_NUM] = {
/*
 * {module_id,
 *  module_type,
 *  module_name,
 *  can_connect,
 *  module_driver,
 *
 *  {reg_dt_name,
 *  reg_pa_check,
 *  reg_irq_check,
 *  irq_max_bit,
 *  reg_va,
 *  reg_irq}
 * },
 */
	{DISP_MODULE_OVL0,
	 DISP_T_OVL,
	 "ovl0",
	 1,
	 NULL,
	 {"mediatek,disp_ovl0",
	  0x14000000,
	  285,
	  14,
	  0,
	  0}
	},

	{DISP_MODULE_OVL0_2L,
	 DISP_T_OVL,
	 "ovl0_2l",
	 1,
	 NULL,
	 {"mediatek,disp_ovl0_2l",
	  0x14001000,
	  286,
	  14,
	  0,
	  0}
	},

	{DISP_MODULE_OVL0_2L_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "ovl0_2l_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_OVL0_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "ovl0_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_RSZ0,
	 DISP_T_RSZ,
	 "rsz0",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_OVL1,
	 DISP_T_OVL,
	 "ovl1",
	 1,
	 NULL,
	 {"mediatek,disp_ovl1",
	  0x14100000,
	  296,
	  14,
	  0,
	  0}
	},

	{DISP_MODULE_OVL1_2L,
	 DISP_T_OVL,
	 "ovl1_2l",
	 1,
	 NULL,
	 {"mediatek,disp_ovl1_2l",
	  0x14101000,
	  297,
	  14,
	  0,
	  0}
	},

	{DISP_MODULE_OVL1_2L_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "ovl1_2l_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_OVL1_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "ovl1_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_RSZ1,
	 DISP_T_RSZ,
	 "rsz0",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_RDMA0,
	 DISP_T_RDMA,
	 "rdma0",
	 1,
	 NULL,
	 {"mediatek,disp_rdma0",
	  0x14003000,
	  287,
	  7,
	  0,
	  0}
	},

	{DISP_MODULE_RDMA0_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "rdma0_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_WDMA0,
	 DISP_T_WDMA,
	 "wdma0",
	 1,
	 NULL,
	 {"mediatek,disp_wdma0",
	  0x14006000,
	  288,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_COLOR0,
	 DISP_T_COLOR,
	 "color0",
	 1,
	 NULL,
	 {"mediatek,disp_color0",
	  0x14007000,
	  289,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_CCORR0,
	 DISP_T_CCORR,
	 "ccorr0",
	 1,
	 NULL,
	 {"mediatek,disp_ccorr0",
	  0x14008000,
	  290,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_RDMA1,
	 DISP_T_RDMA,
	 "rdma1",
	 1,
	 NULL,
	 {"mediatek,disp_rdma1",
	  0x14103000,
	  298,
	  7,
	  0,
	  0}
	},

	{DISP_MODULE_RDMA1_VIRTUAL0,
	 DISP_T_UNKNOWN,
	 "rdma1_virt",
	 1,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_WDMA1,
	 DISP_T_WDMA,
	 "wdma1",
	 1,
	 NULL,
	 {"mediatek,disp_wdma1",
	  0x14106000,
	  299,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_COLOR1,
	 DISP_T_COLOR,
	 "color1",
	 1,
	 NULL,
	 {"mediatek,disp_color1",
	  0x14107000,
	  300,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_CCORR1,
	 DISP_T_CCORR,
	 "ccorr1",
	 1,
	 NULL,
	 {"mediatek,disp_ccorr1",
	  0x14108000,
	  301,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_AAL0,
	 DISP_T_AAL,
	 "aal0",
	 1,
	 NULL,
	 {"mediatek,disp_aal0",
	  0x14009000,
	  291,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_MDP_AAL4,
	 DISP_T_UNKNOWN,
	 "mdp_aal4",
	 1,
	 NULL,
	 {"mediatek,mdp_aal4",
	  0x14010000,
	  317,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_GAMMA0,
	 DISP_T_GAMMA,
	 "gamma0",
	 1,
	 NULL,
	 {"mediatek,disp_gamma0",
	  0x1400a000,
	  292,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_POSTMASK0,
	 DISP_T_POSTMASK,
	 "postmask0",
	 1,
	 NULL,
	 {"mediatek,disp_postmask0",
	  0x1400d000,
	  309,
	  13,
	  0,
	  0}
	},

	{DISP_MODULE_DITHER0,
	 DISP_T_DITHER,
	 "dither0",
	 1,
	 NULL,
	 {"mediatek,disp_dither0",
	  0x1400b000,
	  293,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_AAL1,
	 DISP_T_AAL,
	 "aal1",
	 1,
	 NULL,
	 {"mediatek,disp_aal1",
	  0x14109000,
	  302,
	  1,
	  0,
	  0}
	},

	{DISP_MODULE_MDP_AAL5,
	 DISP_T_UNKNOWN,
	 "mdp_aal5",
	 0,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_GAMMA1,
	 DISP_T_GAMMA,
	 "gamma1",
	 1,
	 NULL,
	 {"mediatek,disp_gamma1",
	  0x1410a000,
	  303,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_POSTMASK1,
	 DISP_T_POSTMASK,
	 "postmask1",
	 1,
	 NULL,
	 {"mediatek,disp_postmask1",
	  0x1410d000,
	  310,
	  13,
	  0,
	  0}
	},

	{DISP_MODULE_DITHER1,
	 DISP_T_DITHER,
	 "dither1",
	 1,
	 NULL,
	 {"mediatek,disp_dither1",
	  0x1410b000,
	  304,
	  0,
	  0,
	  0}
	},

	{DISP_MODULE_SPLIT0,
	 DISP_T_UNKNOWN,
	 "split0",
	 0,
	 NULL,
	 {reg_magic,}
	},

	{DISP_MODULE_DSI0,
	 DISP_T_DSI,
	 "dsi0",
	 1,
	 NULL,
	 {"mediatek,dsi0",
	  0x1400e000,
	  294,
	  15,
	  0,
	  0}
	 },

	{DISP_MODULE_DSI1,
	 DISP_T_DSI,
	 "dsi1",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_DSIDUAL,
	 DISP_T_DSI,
	 "dsidual",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_PWM0,
	 DISP_T_PWM,
	 "pwm0",
	 0,
	 NULL,
	 {"mediatek,disp_pwm0",
	  0x1100E000,
	  151,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_CONFIG,
	 DISP_T_UNKNOWN,
	 "config",
	 0,
	 NULL,
	 {"mediatek,dispsys_config",
	  0x14116000,
	  0,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_MUTEX,
	 DISP_T_UNKNOWN,
	 "mutex",
	 0,
	 NULL,
	 {"mediatek,disp_mutex0",
	  0x14117000,
	  283,
	  21,
	  0,
	  0}
	 },

	{DISP_MODULE_SMI_COMMON,
	 DISP_T_UNKNOWN,
	 "sim_common",
	 0,
	 NULL,
	 {"mediatek,smi_common",
	  0x1411f000,
	  0,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_SMI_LARB0,
	 DISP_T_UNKNOWN,
	 "smi_larb0",
	 0,
	 NULL,
	 {"mediatek,smi_larb0",
	  0x14118000,
	  0,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_SMI_LARB1,
	 DISP_T_UNKNOWN,
	 "smi_larb1",
	 0,
	 NULL,
	 {"mediatek,smi_larb1",
	  0x14119000,
	  0,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_MIPI0,
	 DISP_T_UNKNOWN,
	 "mipi0",
	 0,
	 NULL,
	 {"mediatek,mipi_tx_config0",
	  0x11e50000,
	  0,
	  0,
	  0,
	  0}
	 },

	{DISP_MODULE_MIPI1,
	 DISP_T_UNKNOWN,
	 "mipi1",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_DPI,
	 DISP_T_DPI,
	 "dpi",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	 {DISP_MODULE_OVL2_2L,
	  DISP_T_OVL,
	  "ovl2_2l",
	  1,
	  NULL,
	  {"mediatek,disp_ovl2_2l",
	   0x14002000,
	   307,
	   14,
	   0,
	   0}
	 },

	 {DISP_MODULE_OVL3_2L,
	  DISP_T_OVL,
	  "ovl3_2l",
	  1,
	  NULL,
	  {"mediatek,disp_ovl3_2l",
	   0x14102000,
	   308,
	   14,
	   0,
	   0}
	 },

	 {DISP_MODULE_RDMA4,
	  DISP_T_OVL,
	  "rdma4",
	  1,
	  NULL,
	  {"mediatek,disp_rdma4",
	   0x14005000,
	   327,
	   14,
	   0,
	   0}
	 },

	 {DISP_MODULE_RDMA5,
	  DISP_T_OVL,
	  "rdma5",
	  1,
	  NULL,
	  {"mediatek,disp_rdma5",
	   0x14105000,
	   328,
	   14,
	   0,
	   0}
	 },

	{DISP_MODULE_MDP_RDMA4,
	 DISP_T_UNKNOWN,
	 "mdp_rdma4",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_MDP_RDMA5,
	 DISP_T_UNKNOWN,
	 "mdp_rdma5",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_MDP_RSZ4,
	 DISP_T_UNKNOWN,
	 "mdp_rsz4",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_MDP_RSZ5,
	 DISP_T_UNKNOWN,
	 "mdp_rsz5",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_MERGE0,
	 DISP_T_UNKNOWN,
	 "merge0",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_MERGE1,
	 DISP_T_UNKNOWN,
	 "merge1",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_DP_INTF,
	 DISP_T_UNKNOWN,
	 "dp_intf",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_DSC,
	 DISP_T_UNKNOWN,
	 "dsc",
	 0,
	 NULL,
	 {reg_magic,}
	 },

	{DISP_MODULE_UNKNOWN,
	 DISP_T_UNKNOWN,
	 "unknown",
	 0,
	 NULL,
	 {reg_magic,}
	 },
};

unsigned int is_ddp_module(enum DISP_MODULE_ENUM module)
{
        if (module >= 0 && module < DISP_MODULE_NUM)
                return 1;

        return 0;
}

char *ddp_get_module_name(enum DISP_MODULE_ENUM module)
{
	if (is_ddp_module(module))
		return ddp_modules[module].module_name;

	DDPMSG("%s: invalid module id=%d\n", __func__, module);
	return "unknown";
}

unsigned int _can_connect(enum DISP_MODULE_ENUM module)
{
	if (is_ddp_module(module))
		return ddp_modules[module].can_connect;


	DDPMSG("%s: invalid module id=%d\n", __func__, module);
	return 0;
}
