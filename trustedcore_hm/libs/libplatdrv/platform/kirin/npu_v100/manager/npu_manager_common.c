/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager common
 */

#include "npu_manager_common.h"
#include <errno.h>
#include "drv_log.h"

static struct npu_reg_callbak_info g_reg_cb;

void npu_register_callbak_info_init(void)
{
	int i;

	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		g_reg_cb.op_callback[i] = NULL;
	}

	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		g_reg_cb.rs_callback[i] = NULL;
	}
}

// register callback (what to do when npu power up)
int npu_open_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx)
{
	int i;
	if (callback == NULL || callback_idx == NULL) {
		NPU_ERR("callback or callback_idx is null\n");
		return -ENODEV;
	}

	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		if (g_reg_cb.op_callback[i] == NULL) {
			g_reg_cb.op_callback[i] = callback;
			*callback_idx = i;
			return 0;
		}
	}

	return -ENODEV;
}

// deregister callback (what to do when npu power up),as dev release
int npu_open_npu_callback_dereg(unsigned int callback_idx)
{
	if (callback_idx >= DEVDRV_CALLBACK_REG_NUM) {
		NPU_ERR("callback_idx is invalid %d\n", callback_idx);
		return -ENODEV;
	}

	g_reg_cb.op_callback[callback_idx] = NULL;

	return 0;
}

// when npu power up, call callback
void npu_open_npu_callback_proc(unsigned int dev_id)
{
	int i;
	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		if (g_reg_cb.op_callback[i] != NULL) {
			g_reg_cb.op_callback[i](dev_id);
		}
	}

	return;
}

// register callback (what to do when npu power down)
int npu_release_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx)
{
	int i;
	if (callback == NULL || callback_idx == NULL) {
		NPU_ERR("callback or callback_idx is null\n");
		return -ENODEV;
	}

	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		if (g_reg_cb.rs_callback[i] == NULL) {
			g_reg_cb.rs_callback[i] = callback;
			*callback_idx = i;
			return 0;
		}
	}

	return -ENODEV;
}

// deregister callback (what to do when npu power down),as dev release
int npu_release_npu_callback_dereg(unsigned int callback_idx)
{
	if (callback_idx >= DEVDRV_CALLBACK_REG_NUM) {
		NPU_ERR("callback_idx is invalid %d\n", callback_idx);
		return -ENODEV;
	}

	g_reg_cb.rs_callback[callback_idx] = NULL;

	return 0;
}

// when npu power down, call callback
void npu_release_npu_callback_proc(unsigned int dev_id)
{
	int i;
	for (i = 0; i < DEVDRV_CALLBACK_REG_NUM; i++) {
		if (g_reg_cb.rs_callback[i] != NULL) {
			g_reg_cb.rs_callback[i](dev_id);
		}
	}
	return;
}

