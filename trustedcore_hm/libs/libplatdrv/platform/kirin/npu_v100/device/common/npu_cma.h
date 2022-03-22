/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu creat and free
 */
#ifndef __NPU_CMA_H
#define __NPU_CMA_H

#include "drv_log.h"
#include "npu_common.h"
#include "npu_platform.h"

typedef unsigned long long vir_addr_t;

#define NPU_CMA_ITEM_SIZE	512
#define NPU_CMA_PAGE_SIZE	0x200000
#define NPU_CMA_PAGE_SIZE_ORDER	21

#define NPU_CMA_PAGE_NUM	1	// 1 on teeos

#define NPU_CMA_PAGE_FREE	0
#define NPU_CMA_PAGE_OCCUPIED	1

typedef struct npu_cma_page {
	u64 dma_handle;
	u32 ta_vaddr; // record vaddr map to ta
	u16 state; // 0 free 1 occupied
} npu_cma_page_t;

// reserve cma descriptor
typedef struct npu_rsv_cma_desc {
	npu_cma_page_t pages[NPU_CMA_PAGE_NUM];
	u64 base_addr;
	u32 total_len;
} npu_rsv_cma_desc_t;


int npu_cma_init(u8 dev_id);

int npu_cma_alloc(unsigned int size, u32 *ta_vaddr);

int npu_cma_free(void *vaddr);

int npu_cma_ta_vaddr_to_paddr(void *ta_vaddr, u32 *phy_addr);

int npu_cma_resource_recycle(struct npu_dev_ctx *dev_ctx);

#endif
