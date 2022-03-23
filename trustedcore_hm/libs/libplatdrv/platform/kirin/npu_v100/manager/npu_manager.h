/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager
 */
#ifndef __NPU_MANAGER_H
#define __NPU_MANAGER_H
#include <drv_module.h>
#include <hm_unistd.h>
#include "sre_syscalls_id_ext.h"
#include "sre_access_control.h"
#include "tee_mem_mgmt_api.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "list.h"
#include "npu_spec_share.h"

#define DEVDRV_MANAGER_DEVICE_ENV  0

#define DEVDRV_AI_SUBSYS_SDMA_WORKING_STATUS_OFFSET  5
#define DEVDRV_AI_SUBSYS_SPCIE_WORKING_STATUS_OFFSET 6

typedef struct tag_npu_custom_cmd_to_name {
	uint32_t cmd;
	char* name;
} npu_custom_cmd_to_name_t;

typedef struct tag_npu_io_cmd_to_name {
	uint32_t ioc_nr;
	char* name;
} npu_io_cmd_to_name_t;

struct npu_manager_info {
	/* number of devices probed by pcie */
	u32 prob_num;
	u32 num_dev;

	u32 plat_info;   /* 0:device side, 1: host side */
	u32 dev_id_flag[DEVDRV_MAX_DAVINCI_NUM]; /* get devce id from host */
	u32 dev_id[DEVDRV_MAX_DAVINCI_NUM];      /* device id assigned by host device driver */

	struct list_head pm_list_header;     /* for power manager */
	u32 host_type;
};

struct npu_manager_info *npu_get_manager_info(void);

#endif /* __DEVDRV_MANAGER_H */
