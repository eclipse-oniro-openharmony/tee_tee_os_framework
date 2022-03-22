/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for ChinaDRM module.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#ifndef __CDRM_CMD_H__
#define __CDRM_CMD_H__

#include <eps_ddr_layout_define.h>
#include <soc_acpu_baseaddr_interface.h>

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define HIEPS_DDR_BASE                   (HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_CDRM_DDR_ADDR              (EPS_IPC_TEEOS2EPS_ADDR(HIEPS_DDR_BASE))
#define HIEPS_CDRM_DDR_SIZE              (EPS_IPC_TEEOS2EPS_SIZE)

#define HIEPS_CDRM_MSG_DONE                (0xA7D29C8B)
#define HIEPS_CDRM_MSG_DOING               (~HIEPS_CDRM_MSG_DONE)

typedef struct {
	uint32_t flag;
	uint32_t addr;
	uint32_t size;
} hieps_cdrm_msg_t;
/*===============================================================================
 *                                global objects                               *
===============================================================================*/
extern hieps_cdrm_msg_t g_hieps_cdrm_msg;

/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
uint32_t hieps_send_cdrm_msg(uint32_t addr, uint32_t size);
int32_t hieps_cdrm_init(void);
hieps_cdrm_msg_t hieps_get_cdrm_msg(void);
void hieps_clear_cdrm_msg(void);

#endif /* __CDRM_CMD_H__ */
