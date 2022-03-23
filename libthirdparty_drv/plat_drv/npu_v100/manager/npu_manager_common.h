/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager common
 */

#ifndef __NPU_MANAGER_COMMON_H
#define __NPU_MANAGER_COMMON_H

#include <sre_typedef.h>
#include "drv_log.h"
#define DEVDRV_CALLBACK_REG_NUM		10

struct npu_reg_callbak_info {
	int (*op_callback[DEVDRV_CALLBACK_REG_NUM])(unsigned int dev_id); // power up callback
	int (*rs_callback[DEVDRV_CALLBACK_REG_NUM])(unsigned int dev_id); // power down callback
};

void npu_register_callbak_info_init(void);
int npu_open_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx);
int npu_open_npu_callback_dereg(unsigned int callback_idx);
void npu_open_npu_callback_proc(unsigned int dev_id);
int npu_release_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx);
int npu_release_npu_callback_dereg(unsigned int callback_idx);
void npu_release_npu_callback_proc(unsigned int dev_id);

#define DEVDRV_MANAGER_MSG_VALID	0x5A5A
#define DEVDRV_MANAGER_MSG_INVALID_RESULT		0x1A

enum {
	DEVDRV_MANAGER_CHAN_H2D_SEND_DEVID,
	DEVDRV_MANAGER_CHAN_D2H_DEVICE_READY,
	DEVDRV_MANAGER_CHAN_D2H_DEVICE_READY_AND_TS_WORK,
	DEVDRV_MANAGER_CHAN_D2H_DOWN,
	DEVDRV_MANAGER_CHAN_D2H_SUSNPEND,
	DEVDRV_MANAGER_CHAN_D2H_RESUME,
	DEVDRV_MANAGER_CHAN_D2H_FAIL_TO_SUSPEND,
	DEVDRV_MANAGER_CHAN_D2H_CORE_INFO,
	DEVDRV_MANAGER_CHAN_H2D_HEART_BEAT,
	DEVDRV_MANAGER_CHAN_D2H_GET_PCIE_ID_INFO,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_STREAM,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_STREAM,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_EVENT,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_EVENT,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_SQ,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_SQ,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_CQ,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_CQ,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_MODEL,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_MODEL,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_NOTIFY,
	DEVDRV_MANAGER_CHAN_D2H_SYNC_GET_NOTIFY,
	DEVDRV_MANAGER_CHAN_H2D_SYNC_GET_DEVINFO,
	DEVDRV_MANAGER_CHAN_H2D_CONTAINER,
	DEVDRV_MANAGER_CHAN_H2D_GET_TASK_STATUS,
	DEVDRV_MANAGER_CHAN_H2D_LOAD_KERNEL,
	DEVDRV_MANAGER_CHAN_D2H_LOAD_KERNEL_RESULT,
	DEVDRV_MANAGER_CHAN_MAX_ID,
};

static inline u64 npu_read_cntpct(void)
{
	u64 cntpct;
	asm volatile("mrs %0, cntpct_el0" : "=r" (cntpct));
	return cntpct;
}

void npu_register_callbak_info_init(void);
int npu_open_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx);
int npu_open_npu_callback_dereg(unsigned int callback_idx);
void npu_open_npu_callback_proc(unsigned int dev_id);
int npu_release_npu_callback_reg(int (*callback) (unsigned int dev_id), unsigned int *callback_idx);
int npu_release_npu_callback_dereg(unsigned int callback_idx);
void npu_release_npu_callback_proc(unsigned int dev_id);

// copy data from HIAI trust application to the plat drv special TA
static inline int copy_from_TA_safe(void *to, const void *from, unsigned long n)
{
	int bytes;
	int i;
	u8 *tmpto = NULL;
	u8 *tmpfrom = NULL;

	if (from == NULL || n == 0) {
		NPU_ERR("HIAI TA pointer is NULL\n");
		return -1;
	}

	bytes = n;
	tmpto = (u8 *)to;
	tmpfrom = (u8 *)from;

	for (i = 0; i < bytes; i++) {
		*tmpto = *tmpfrom;
		tmpto++;
		tmpfrom++;
	}
	return 0;
}

// copy data to HIAI trust application from the plat drv special TA
static inline int copy_to_TA_safe(void *to, const void *from, unsigned long n)
{
	int bytes;
	int i = 0;
	u8 *tmpto = NULL;
	u8 *tmpfrom = NULL;

	if (to == NULL || n == 0) {
		NPU_ERR("HIAI pointer is NULL\n");
		return -1;
	}

	bytes = n;
	tmpto = (u8 *)to;
	tmpfrom = (u8 *)from;

	for (i = 0; i < bytes; i++) {
		*tmpto = *tmpfrom;
		tmpto++;
		tmpfrom++;
	}
	return 0;
}

#endif /* __NPU_MANAGER_COMMON_H */
