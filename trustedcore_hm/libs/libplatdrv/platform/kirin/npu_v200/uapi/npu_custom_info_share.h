/*
 * npu_custom_info_share.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_CUSTOM_INFO_SHARE_H__
#define __NPU_CUSTOM_INFO_SHARE_H__
#include "npu_base_define.h"

#define NPU_SECMEM_SHARED_CONFIG_LEN 0x1000

#define DEVDRV_PLAT_TYPE_FPGA (0x0)
#define DEVDRV_PLAT_TYPE_EMU (0x1)
#define DEVDRV_PLAT_TYPE_ESL (0x2)
#define DEVDRV_PLAT_TYPE_ASIC (0x3)

#define DEVDRV_PLAT_DEVICE 0
#define DEVDRV_CTRL_CPU_ID (0x41D05)
typedef struct npu_unmap_ta_vaddr {
	uintptr_t ta_vaddr;
	u32 size;
} npu_unmap_ta_vaddr_t;

typedef struct npu_ops_release_info {
	int fd;
} npu_ops_release_info_t;

typedef struct npu_ops_ioctl_info {
	int fd;
	unsigned int cmd;
	unsigned int *param;
	unsigned int param_size; /* indicate param mem size */
} npu_ops_ioctl_info_t;

typedef struct npu_stream_alloc_info {
	u16 strategy;
	u16 priority;
	int stream_id;
} npu_stream_alloc_info_t;

typedef struct npu_device_info {
	uint8_t envType; /* 0: FPGA  1: EMU 2: ESL */
	unsigned int ctrl_cpu_ip;
	unsigned int ctrl_cpu_id;
	unsigned int ctrl_cpu_core_num;
	unsigned int ctrl_cpu_endian_little;
	unsigned int tscpu_core_num;
	unsigned int aicpu_core_num;
	unsigned int aicore_num;
	unsigned int aicpu_core_id;
	unsigned int aicore_id;
	unsigned int aicpu_occupy_bitmap;
} npu_device_info_t;

typedef enum {
	DEVDRV_IOC_VA_TO_PA,				/* current only use in lite */
	DEVDRV_IOC_GET_SVM_SSID,			/* current only use in lite */
	DEVDRV_IOC_GET_CHIP_INFO,			/* current only use in lite */
	DEVDRV_IOC_ALLOC_CONTIGUOUS_MEM,	/* current only use in lite */
	DEVDRV_IOC_FREE_CONTIGUOUS_MEM,		/* current only use in lite */
	DEVDRV_IOC_GET_SHM_MEM_TA_VADDR,	/* get sq cq info db mem ta vaddr */
	DEVDRV_IOC_MMAP_PHY_MEM_TA_VADDR,	/* map phy mem in platdrv and return TA vaddr to TA */
	DEVDRV_IOC_UNMAP_TA_VADDR,		/* unmap TA vaddr mapped in platdrv */
	DEVDRV_IOC_POWERUP,
	DEVDRV_IOC_POWERDOWN,
	DEVDRV_IOC_REBOOT,
	DEVDRV_IOC_LOAD_MODEL_BUFF,         /* load stream buff of model */
	DEVDRV_IOC_CUSTOM_MAX,
} npu_custom_ioc_t;

typedef struct npu_custom_para {
	u32 version;
	u32 cmd;
	u32 result;
	u32 arg_size;
	u64 arg;
} npu_custom_para_t;

typedef struct npu_process_info {
	s32 vpid;
	u64 ttbr;
	u64 tcr;
	unsigned int pasid;
	u32 flags;
} npu_process_info_t;

struct npu_chip_info {
	UINT32 l2_size;
	UINT32 reserved[3];
};

typedef struct npu_model_desc {
	u16 model_id;
	u16 stream_cnt;
	u16 stream_id[NPU_MODEL_STREAM_NUM];
	u16 stream_tasks[NPU_MODEL_STREAM_NUM];
	void *stream_addr[NPU_MODEL_STREAM_NUM];
} npu_model_desc_t;

typedef struct npu_secure_info {
	uint32_t secure_mode;
} npu_secure_info_t;

enum {
	STREAM_STRATEGY_NONSINK = 0,
	STREAM_STRATEGY_SINK = 1,
	STREAM_STRATEGY_MAX
};

struct npu_stream_strategy_ioctl_info {
	int stream_id;
	u32 strategy;
	u32 devid;
};

enum {
	NPU_SEC_FEATURE_UNSUPPORTED = 0,
	NPU_SEC_FEATURE_SUPPORTED,
};

typedef union {
	struct {
		uint32_t npu_sec_enable;
	} cfg;
	unsigned char reserved[NPU_SECMEM_SHARED_CONFIG_LEN];
} npu_secmem_head;

typedef struct ta_vm_area {		/* The first cache line has the info for VMA tree walking. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address within vm_mm. */
	unsigned int vm_page_prot;		/* Access permissions of this VMA. */
	unsigned int vm_flags;		/* Flags, see mm.h. */
	/* Information about our backing store: */
	unsigned int vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE units */
	unsigned long ta_vaddr_after_drv_map;  /* output para */
} ta_vm_area_t;
#endif /* __NPU_CUSTOM_INFO_SHARE_H__ */
