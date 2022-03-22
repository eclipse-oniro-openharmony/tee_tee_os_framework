/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager ioctl services
 */

#include "npu_manager_ioctl_services.h"

#include <errno.h>
#include <stdint.h>

#include "drv_log.h"
#include "npu_spec_share.h"
#include "npu_custom_info_share.h"
#include "npu_io_cmd_share.h"
#include "npu_manager_common.h"
#include "npu_platform.h"

static int npu_manager_ioctl_get_devnum(int fd, unsigned int cmd, unsigned long arg)
{
	UNUSED(fd);
	UNUSED(cmd);
	u32 devnum;

	devnum = 1;
	if (copy_to_TA_safe((void *)(uintptr_t)arg, &devnum, sizeof(u32))) {
		return -EFAULT;
	} else {
		return 0;
	}
}

static int npu_manager_ioctl_get_plat_info(int fd, unsigned int cmd, unsigned long arg)
{
	UNUSED(fd);
	u32 plat_type;
	struct npu_platform_info *plat_info = npu_plat_get_info();

	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info failed\r\n");
		return -EFAULT;
	}

	plat_type = (u32)DEVDRV_PLAT_GET_TYPE(plat_info);
	if (copy_to_TA_safe((void *)(uintptr_t)arg, &plat_type, sizeof(u32))) {
		NPU_ERR("cmd, cmd = %u copy plat_info to user failed \n", _IOC_NR(cmd));
		return -EFAULT;
	}

	return 0;
}

static int npu_manager_get_devinfo(unsigned long arg)
{
	struct npu_manager_hccl_devinfo hccl_devinfo = {0};
	struct npu_platform_info *plat_info = npu_plat_get_info();

	NPU_DEBUG("npu_manager_get_devinfo start\n");

	COND_RETURN_ERROR(plat_info == NULL, -EFAULT, "npu_plat_get_info failed\r\n");
	COND_RETURN_ERROR(copy_from_TA_safe(&hccl_devinfo, (void *)(uintptr_t)arg, sizeof(hccl_devinfo)), -1,
		"copy hccl_devinfo from user failed\n");

	// get plat
	hccl_devinfo.ts_cpu_core_num = 1;

	hccl_devinfo.ai_core_num = DEVDRV_PLAT_GET_AICORE_MAX(plat_info);
	hccl_devinfo.ai_core_id = 0;

	hccl_devinfo.ai_cpu_core_num = DEVDRV_PLAT_GET_AICPU_MAX(plat_info);
	hccl_devinfo.ai_cpu_bitmap = 0x1;
	hccl_devinfo.ctrl_cpu_id = 0x41D05;
	hccl_devinfo.ctrl_cpu_ip = 0;

	/* 1:little endian 0:big endian */
#if defined(__LITTLE_ENDIAN)
	hccl_devinfo.ctrl_cpu_endian_little = 1;
#elif defined(__BIG_ENDIAN)
	hccl_devinfo.ctrl_cpu_endian_little = 0;
#endif

	hccl_devinfo.env_type = DEVDRV_PLAT_GET_ENV(plat_info);
	hccl_devinfo.hardware_version = DEVDRV_PLAT_GET_HARDWARE(plat_info);

	NPU_DEBUG("print npu dev info msg :"
		"hccl_devinfo.ts_cpu_core_num = %d \n hccl_devinfo.ai_core_num = %d "
		"hccl_devinfo.ai_core_id = %d \n hccl_devinfo.ai_cpu_core_num = %d "
		"hccl_devinfo.ai_cpu_bitmap = %d hccl_devinfo.ai_cpu_core_id = %d \n"
		"hccl_devinfo.ctrl_cpu_core_num = %d hccl_devinfo.ctrl_cpu_ip = %d "
		"hccl_devinfo.ctrl_cpu_id = 0x%x hccl_devinfo.ctrl_cpu_endian_little = %d \n"
		"hccl_devinfo.env_type = %d hccl_devinfo.hardware_version = 0x%x \n",
		hccl_devinfo.ts_cpu_core_num, hccl_devinfo.ai_core_num,
		hccl_devinfo.ai_core_id, hccl_devinfo.ai_cpu_core_num,
		hccl_devinfo.ai_cpu_bitmap, hccl_devinfo.ai_cpu_core_id,
		hccl_devinfo.ctrl_cpu_core_num, hccl_devinfo.ctrl_cpu_id,
		hccl_devinfo.ctrl_cpu_ip, hccl_devinfo.ctrl_cpu_endian_little,
		hccl_devinfo.env_type, hccl_devinfo.hardware_version);

	COND_RETURN_ERROR(copy_to_TA_safe((void *)(uintptr_t)arg, &hccl_devinfo, sizeof(hccl_devinfo)), -EFAULT,
		"copy hccl_devinfo to user error\n");

	return 0;
}

int npu_get_devids(u32 *devices)
{
	u8 i;
	u8 j = 0;

	if (devices == NULL) {
		return -1;
	}

	/* get device id assigned from host, default dev_id is 0 if there is no host */
	for (i = 0; i < DEVDRV_MAX_DAVINCI_NUM; i++) {
		devices[j++] = i;
	}

	if (j == 0) {
		NPU_ERR("NO dev_info!!!\n");
		return -EFAULT;
	}

	return 0;
}


static int npu_manager_get_devids(unsigned long arg)
{
	struct npu_manager_hccl_devinfo hccl_devinfo = {0};

	hccl_devinfo.num_dev = 1;
	if (npu_get_devids(hccl_devinfo.devids)) {
		NPU_ERR("npu_get_devids failed\n");
		return -1;
	}
	if (copy_to_TA_safe((void *)(uintptr_t)arg, &hccl_devinfo, sizeof(hccl_devinfo))) {
		NPU_ERR("copy from user failed\n");
		return -1;
	}

	return 0;
}


static int npu_manager_devinfo_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	UNUSED(fd);
	int ret;

	switch (cmd) {
		case DEVDRV_MANAGER_GET_DEVIDS:
			ret = npu_manager_get_devids(arg);
			break;
		case DEVDRV_MANAGER_GET_DEVINFO:
			ret = npu_manager_get_devinfo(arg);
			break;
		default:
			ret = -1;
			break;
	}

	return ret;
}

static int (*const npu_manager_ioctl_handlers[DEVDRV_MANAGER_CMD_MAX_NR]) (int fd, unsigned int cmd, unsigned long arg)
	= {
	[_IOC_NR(DEVDRV_MANAGER_GET_DEVNUM)] = npu_manager_ioctl_get_devnum,
	[_IOC_NR(DEVDRV_MANAGER_GET_PLATINFO)] = npu_manager_ioctl_get_plat_info,
	[_IOC_NR(DEVDRV_MANAGER_GET_DEVIDS)] = npu_manager_devinfo_ioctl,
	[_IOC_NR(DEVDRV_MANAGER_GET_DEVINFO)] = npu_manager_devinfo_ioctl,
};

long npu_manager_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
 	NPU_DEBUG("npu_manager_ioctl start IOC_NR = %d cmd = %d \n", _IOC_NR(cmd), cmd);
	if (_IOC_NR(cmd) >= DEVDRV_MANAGER_CMD_MAX_NR) {
		NPU_ERR("invalid cmd, cmd = %u\n", _IOC_NR(cmd));
		return -1;
	}

	if (!npu_manager_ioctl_handlers[_IOC_NR(cmd)]) {
		NPU_ERR("invalid cmd, cmd = %u\n", _IOC_NR(cmd));
		return -1;
	}

	return npu_manager_ioctl_handlers[_IOC_NR(cmd)](fd, cmd, arg);
}

