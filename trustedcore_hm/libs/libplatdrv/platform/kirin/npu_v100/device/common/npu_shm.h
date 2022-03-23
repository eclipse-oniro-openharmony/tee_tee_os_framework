/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu map and unmap
 */
#ifndef __NPU_SHM_H
#define __NPU_SHM_H

#include "npu_custom_info_share.h"
#include "npu_platform.h"
#include "npu_common.h"
#include "drv_log.h"

extern struct npu_mem_desc g_sq_desc;

typedef unsigned long long vir_addr_t;

typedef struct npu_shm_entry {
	u64 phy_addr;
	u32 drv_vaddr;
	uintptr_t ta_vaddr;
	u32 size;
} npu_shm_entry_t;

enum npu_shm_type {
	NPU_SHM_SQ,
	NPU_SHM_CQ,
	NPU_SHM_PERSISTENT_TASK_BUFF, // task puff
	NPU_SHM_TSCPU_LOG, // tscpu log map for hiai ta
	NPU_SHM_INFO, // stream info ã€?sq info ã€cq info
	NPU_SHM_DB, // doorbell
	NPU_SHM_POWER_STATUS, //power status reg
	NPU_SHM_TYPES
};

struct npu_mem_info {
	u64 phy_addr;
	vir_addr_t virt_addr;
	size_t size;
};

enum {
	DEVDRV_SQ_MEM = 0,
	DEVDRV_INFO_MEM,
	DEVDRV_DOORBELL_MEM,
	DEVDRV_MAX_MEM
};

// bit8~15 map_type, bit0~7 share num
// for npu drv mmap switch identify
#define MAP_COMBINE(type, share_num)   ((type << 8) | (share_num))
#define MAP_GET_TYPE(map_info)                  (((map_info) >> 8) & 0xff)
#define MAP_GET_SHARE_NUM(map_info)               ((map_info) & 0xff)
#define SHM_POWER_STATUS_SIZE                     4

typedef enum {
	MAP_RESERVED = 0,
	MAP_L2_BUFF,
	MAP_CONTIGUOUS_MEM,
	MAP_INFO_SQ_CQ_MEM, // map info desc(streamã€sqã€cq) sq channel and cq channel( delete doorbell mmap)
	MAP_MAX,
} npu_map_type_t;

int npu_shm_init(u8 dev_id);

struct npu_stream_info *npu_calc_stream_info(u8 devid, u32 index);

struct npu_ts_sq_info *npu_calc_sq_info(u8 devid, u32 index);

struct npu_ts_cq_info *npu_calc_cq_info(u8 devid, u32 index);

u32 *npu_get_ts_work_status(u8 devid, u32 index);

void npu_shm_destroy(u8 dev_id);

int npu_dev_map(u8 dev_id, ta_vm_area_t* vma);

int npu_dev_unmap(uint32_t vaddr, uint32_t size);

int npu_map_cm(ta_vm_area_t* vma, u32 share_num, u8 dev_id);

// map sq ã€cq ã€?db ã€info ã€persistent task buffã€tscpu log
int npu_shm_mmap(u8 dev_id, npu_shm_vaddr_t* shm_vaddrs);

// unmap sq ã€cq ã€?db ã€info ã€persistent task buffã€tscpu log
int npu_shm_unmap(u8 dev_id);

void npu_clear_mem_data(void *addr, u32 size);

int npu_map_internal_reg(struct npu_dev_ctx *dev_ctx);

void npu_unmap_internal_reg(struct npu_dev_ctx *dev_ctx);

int npu_doorbell_mmap(u8 dev_id, uintptr_t* db_vaddr);

int npu_doorbell_unmap(u8 dev_id);

int npu_reg_map(u8 dev_id, uintptr_t* db_vaddr, enum npu_shm_type type);

int nnpu_reg_unmap(u8 dev_id, enum npu_shm_type type);

int npu_power_status_mmap(u8 dev_id, uintptr_t* power_status_vaddr);

int npu_power_status_unmap(u8 dev_id);

int npu_flush_smmu_tlb(u8 dev_id);

#endif
