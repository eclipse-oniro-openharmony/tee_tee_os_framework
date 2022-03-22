/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "drv_mem.h" /* ACCESS_READ */
#include "register_ops.h" /* writel */
#include "tee_log.h" /* uart_printf_func */
#include "hisi_hdcp_common.h"

static int hdcp_read_reg(unsigned int base_addr, unsigned int offset_max, unsigned int offset)
{
	if (offset > offset_max) {
		uart_printf_func("ERROR!!!,the offset is out of range, and line is %d\n", __LINE__);
		return -1;
	}
	if (tee_mmu_check_access_rights(ACCESS_READ, base_addr + offset, sizeof(int))) {
		uart_printf_func("ERROR!!!!, it seems the input buffer read denied line is %d\n", __LINE__);
		return -1;
	}
	return readl(base_addr + offset);
}

static int hdcp_write_reg(unsigned int base_addr, unsigned int offset_max,
	unsigned int reg_value, unsigned int offset)
{
	if (offset > offset_max) {
		uart_printf_func("ERROR!!!,the offset is out of range, and line is %d\n", __LINE__);
		return -1;
	}
	if (tee_mmu_check_access_rights(ACCESS_WRITE, base_addr + offset, sizeof(int))) {
		uart_printf_func("ERROR!!!!, it seems the input buffer write denied line is %d\n", __LINE__);
		return -1;
	}
	writel(reg_value, base_addr + offset);
	return 0;
}

int hdcp_get_value(unsigned int offset)
{
	return hdcp_read_reg(HDCP_BASE_ADDR, HDCP_OFFSET_MAX, offset);
}

int hdcp_set_reg(unsigned int reg_value, unsigned int offset)
{
	return hdcp_write_reg(HDCP_BASE_ADDR, HDCP_OFFSET_MAX, reg_value, offset);
}

int hdcp_get_dss_value(unsigned int offset)
{
	return hdcp_read_reg(HDCP_DSS_BASE_ADDR, HDCP_DSS_OFFSET_MAX, offset);
}

int hdcp_set_dss_reg(unsigned int reg_value, unsigned int offset)
{
	return hdcp_write_reg(HDCP_DSS_BASE_ADDR, HDCP_DSS_OFFSET_MAX, reg_value, offset);
}
