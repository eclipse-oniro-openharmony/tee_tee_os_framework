/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sec smmu common
 * Author: jianfujian
 * Create: 2020-3-1
 */

#ifndef __HISI_SEC_SMMU_COM_H
#define __HISI_SEC_SMMU_COM_H

#include <sys/hm_types.h>
#include <stdbool.h>
#include <sre_typedef.h>

enum sec_smmu_id {
	SMMU_MEDIA1,
	SMMU_MEDIA2,
	SMMU_NPU,
	SMMU_MAX
};

struct secsmmu_info {
	u32 smmuid;
	u32 sid;
	u32 ssid;
};

struct sec_smmu_para {
	u16 sid;
	u16 ssid;
	pid_t pid;
	u32 smmuid;
	u64 ttbr;
	u64 tcr;
};

/* STREAMID CONFIG */
/* MEDIA1 */
#define SECSMMU_STREAMID_DSS	1
#define SECSMMU_STREAMID_ISP	3
#define SECSMMU_STREAMID_BYPASS 62

/* MEDIA2 */
#define SECSMMU_STREAMID_VCODEC	9
#define SECSMMU_STREAMID_EPS	10
#define SECSMMU_STREAMID_IVP    11

/* NPU */
#define SECSMMU_STREAMID_NPU    16

/* SUBSTREAMID CONFIG */
/* MEDIA1 */
#define SECSMMU_SUBSTREAMID_DSS	1
#define SECSMMU_SUBSTREAMID_ISP	2

/* MEDIA2 */
#define SECSMMU_SUBSTREAMID_VDEC	0
#define SECSMMU_SUBSTREAMID_VENC	1
#define SECSMMU_SUBSTREAMID_EPS		2
#define SECSMMU_SUBSTREAMID_IVP		6


int sec_smmu_poweron(u32 smmuid);
int sec_smmu_poweroff(u32 smmuid);
int sec_smmu_bind(u32 smmuid, u32 sid, u32 ssid, pid_t pid);
int sec_smmu_unbind(u32 smmuid, u32 sid, u32 ssid);
void secsmmu_tlb_inv_asid(u32 smmu_id, u32 sid, u32 ssid);
void secsmmu_tlb_inv_va_range(u32 smmuid, unsigned long iova,
				size_t size, bool leaf);
#endif
