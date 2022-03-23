/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager ioctl services
 */
#ifndef __NPU_MANAGER_IOCTL_SERVICE_H
#define __NPU_MANAGER_IOCTL_SERVICE_H
#include <list.h>
struct npu_device_info {
	u8 env_type;

	u8 ai_cpu_ready_num;
	u8 ai_cpu_broken_map;
	u8 ai_core_ready_num;
	u8 ai_core_broken_map;
	u8 ai_subsys_ip_map;

	u32 ctrl_cpu_ip;
	u32 ctrl_cpu_id;
	u32 ctrl_cpu_core_num;
	u32 ctrl_cpu_endian_little;
	u32 ts_cpu_core_num;
	u32 ai_cpu_core_num;
	u32 ai_core_num;
	u32 ai_cpu_core_id;
	u32 ai_core_id;
	u32 aicpu_occupy_bitmap;

	u32 ts_load_fail;

	u32 min_sq_id;
	u32 max_sq_id;
	u32 min_cq_id;
	u32 max_cq_id;
	u32 min_stream_id;
	u32 max_stream_id;
	u32 min_event_id;
	u32 max_event_id;

	u32 res[5];
};

long npu_manager_ioctl(int fd, unsigned int cmd, unsigned long arg);
#endif /* __DEVDRV_MANAGER_H */

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif /* UNUSED */
