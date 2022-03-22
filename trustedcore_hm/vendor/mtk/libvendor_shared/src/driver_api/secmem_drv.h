/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, secmem driver
 * Author: h00424236
 * Create: 2019-11-08
 */
#ifndef LIBTEE_DRIVER_API_SECMEM_DRV_H
#define LIBTEE_DRIVER_API_SECMEM_DRV_H
#include "dynion.h" // struct sglist

#ifdef TEE_SUPPORT_TZMP2
/* sec_mem */
int __sion_ioctl(int ion_ta_tag, void *mcl);
unsigned int sion_mmap(void *sglist, unsigned int size, unsigned int protect_id, int mode, int cached, int used_by_ta);
int sion_munmap(void *sglist, unsigned int va, unsigned int size, unsigned int protect_id, int mode, int used_by_ta);
int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type);
#endif
#endif /* LIBTEE_DRIVER_API_SECMEM_DRV_H */
