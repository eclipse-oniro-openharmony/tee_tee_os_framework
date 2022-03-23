/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 */
#include <bsp_icc.h>
#include <icc_platform.h>

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650) /* stub */
int bsp_icc_event_register(unsigned int channel_id, read_cb_func read_cb, void *read_context, write_cb_func write_cb, void *write_context)
{
	icc_print_error("is stub\n");
	return ICC_OK;
}

int bsp_icc_send(unsigned int cpuid, unsigned int channel_id, unsigned char *buffer, unsigned int data_len)
{
	icc_print_error("is stub\n");
	return data_len;
}

int bsp_icc_read(unsigned int channel_id, unsigned char *buf, unsigned int buf_len)
{
	icc_print_error("is stub\n");
	return buf_len;
}

#endif
