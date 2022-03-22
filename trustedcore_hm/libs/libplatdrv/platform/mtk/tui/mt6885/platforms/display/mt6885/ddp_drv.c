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

#define LOG_TAG "ddp_drv"
#include "ddp_drv.h"


/* device and driver */
/*volatile unsigned int dispsys_irq[DISP_REG_NUM] = {0};*/
volatile unsigned long dispsys_reg[DISP_REG_NUM] = {0};
volatile unsigned long mipi_tx0_reg = 0;
volatile unsigned long mipi_tx1_reg = 0;
volatile unsigned long dsi_reg_va = 0;

/* from DTS, for debug */
unsigned long ddp_reg_pa_base[DISP_REG_NUM] = {
	0x14116000,	/* CONFIG */
	0x14000000,	/* OVL0 */
	0x14001000,	/* OVL0_2L */
	0x14101000, /* OVL1_2L */
	0x14003000,	/* RDMA0 */
	0x14103000,	/* RDMA1 */
	0x14006000,	/* WDMA0 */
	0x14007000,	/* COLOR0 */
	0x14008000,	/* CCORR0 */
	0x14009000,	/* AAL0 */
	0x1400a000,	/* GAMMA0 */
	0x1400b000,	/* DITHER0 */
	0x1400e000,	/* DSI0 */
	0x14125000, /* DPI */
	0x14117000,	/* MUTEX*/
	0x14118000,	/* SMI_LARB0 */
	0x14119000,	/* SMI_LARB1 */
	0x1411f000,	/* SMI_COMMON */
	0x1400c000, /* RSZ0 */
	0x1400d000, /* POSTMASK */
	0x1100e000,	/* PWM0*/
	0x11e50000,	/* MIPITX0*/
	0x11e60000,	/* MIPITX1*/
};

int disp_reg_init(void)
{
	int ret;
	int i;
    static unsigned int disp_probe_cnt = 0;

    if(disp_probe_cnt!=0)
    {
		disp_probe_cnt = 1;
        return 0;
    }

    /* iomap registers */
    for(i=0;i<DISP_REG_NUM;i++)
    {
		drApiResult_t ret;
		/* remap registers */

        ret = dr_api_map_io(ddp_reg_pa_base[i], 0x1000,
                            MAP_HARDWARE, (void **)&dispsys_reg[i]);

		if(ret != DRAPI_OK)
			DDPAEE("map reg fail: pa=0x%x, size=0x%x, flag=0x%x, ret=%d(0x%x)\n",
				ddp_reg_pa_base[i], 0x1000, MAP_HARDWARE, ret, ret);

        DDPERR("reg_map%d map_addr=%p, reg_pa=0x%x\n",
            i, dispsys_reg[i], ddp_reg_pa_base[i]);
    }

	ddp_path_init();
	ddp_dsi_reg_init();
	DDPMSG("dispsys probe done.\n");
	return 0;
}

int disp_get_version(void)
{
	if (!rdma_is_mem_mode(DISP_MODULE_RDMA0)){
		return MULTI_WINDOWS_TUI;
	}

	return SINGLE_WINDOWS_TUI;
}
