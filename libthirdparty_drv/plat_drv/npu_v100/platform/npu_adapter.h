/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description:about npu adapter
 */

#ifndef DEVDRV_ADAPTER_H
#define DEVDRV_ADAPTER_H

#include "drv_log.h"

enum {
	NPU_SEC_FEATURE_UNSUPPORTED = 0,
	NPU_SEC_FEATURE_SUPPORTED,
};

int npu_plat_power_up(void *svm_dev);

int npu_plat_power_down(void *svm_dev);

int npu_plat_res_mailbox_send(void *mailbox, int mailbox_len, const void *message, int message_len);

int npu_plat_aicore_get_disable_status(int core_id);

int npu_plat_sec_enable_status(void);
#endif
