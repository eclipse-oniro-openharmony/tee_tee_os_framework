/*
 * hisilicon ISP driver, hisp_mem.h
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#ifndef _KIRIN_ISP_HISP_MEM_H_
#define _KIRIN_ISP_HISP_MEM_H_

#include <register_ops.h>
#include "secmem_priv.h"
#include "mem_page_ops.h"

enum secisp_mem_type {
	SECISP_TEXT = 0,
	SECISP_DATA,
	SECISP_SEC_POOL,
	SECISP_ISPSEC_POOL,
	SECISP_DYNAMIC_POOL,
	SECISP_RDR,
	SECISP_SHRD,
	SECISP_VQ,
	SECISP_VR0,
	SECISP_VR1,
	SECISP_MAX_TYPE
};

typedef struct isp_ion_mem_type {
	unsigned int type;
	unsigned int da;
	unsigned int size;
	unsigned int prot;
	unsigned int sec_flag;/* SEC or NESC*/
	int sharefd;
	UINT64 pa;
} secisp_mem_info;

UINT32 hisp_nonsec_mem_map(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl);
UINT32 hisp_nonsec_mem_unmap(struct smmu_domain *domain, secisp_mem_info *buffer, struct sglist *sgl);
UINT32 hisp_sec_mem_map(secisp_mem_info *buffer, UINT32 sfd);
UINT32 hisp_sec_mem_unmap(secisp_mem_info *buffer, UINT32 sfd);

#endif

