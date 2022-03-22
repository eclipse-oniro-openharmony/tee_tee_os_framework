/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, secmem driver
 * Create: 2019-11-08
 */
#ifndef LIBTEE_DRIVER_API_SECMEM_DRV_H
#define LIBTEE_DRIVER_API_SECMEM_DRV_H
#include "dynion.h" // struct sglist

enum SEC_Task {
	SEC_TASK_DRM = 0x0,
	SEC_TASK_SEC,
	SEC_TASK_TINY,
	SEC_TASK_MAX,
};

#ifdef TEE_SUPPORT_TZMP2
/* sec_mem */
int __sion_ioctl(int ion_ta_tag, void *mcl);
unsigned int sion_mmap(void *sglist, unsigned int size, unsigned int protect_id, int mode, int cached, int used_by_ta);
int sion_munmap(void *sglist, unsigned int va, unsigned int size, unsigned int protect_id, int mode, int used_by_ta);
int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);


extern int sion_create_smmu_domain(u32 protect_id,
				   u64 pgtable_addr, u32 pgtable_size);
extern int sion_destroy_smmu_domain(u32 protect_id);

#endif

extern int secmem_smmu_domain_init(uint32_t sid, uint32_t size);
extern int secmem_smmu_domain_destroy(uint32_t sid);

int secmem_get_version(void);
/* same as secmem_api.h */
enum {
	VERSION_1 = 1,
	VERSION_2 = 2,
};

#endif /* LIBTEE_DRIVER_API_SECMEM_DRV_H */
