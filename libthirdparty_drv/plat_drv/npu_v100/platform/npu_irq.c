/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu irq
 */

#include "npu_irq.h"
#include "drv_log.h"
#include "npu_platform_resource.h"

int npu_plat_parse_irq(struct npu_platform_info *plat_info)
{
	DEVDRV_PLAT_GET_CQ_UPDATE_IRQ(plat_info) = IRQ_CALC_CQ_UPDATE0;
	DEVDRV_PLAT_GET_DFX_CQ_IRQ(plat_info) = IRQ_DFX_CQ_UPDATE;
	DEVDRV_PLAT_GET_MAILBOX_ACK_IRQ(plat_info) = IRQ_MAILBOX_ACK;
	NPU_DEBUG("calc_cq_update0=%d\n", DEVDRV_PLAT_GET_CQ_UPDATE_IRQ(plat_info));
	NPU_DEBUG("dfx_cq_update=%d\n", DEVDRV_PLAT_GET_DFX_CQ_IRQ(plat_info));
	NPU_DEBUG("mailbox_ack=%d\n", DEVDRV_PLAT_GET_MAILBOX_ACK_IRQ(plat_info));
	return 0;
}
