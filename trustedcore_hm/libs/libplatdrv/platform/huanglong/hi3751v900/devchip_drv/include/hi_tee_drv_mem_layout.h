/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: sec mem config ext api
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __HI_TEE_DRV_MEM_LAYOUT_H
#define __HI_TEE_DRV_MEM_LAYOUT_H

#define NON_SEC_OS_MEM          0
#define SEC_OS_MEM              1
#define SEC_MMZ_MEM             2
#define NON_SEC_MMZ_MEM         3
#define SEC_SMMU_MMZ            4
#define SEC_MEM_RANGE           5
#define TOTAL_MEM_RANGE         6
#define SEC_OS_CODE_RANGE       7
#define SEC_MEM_VERIFY_RANGE    8

unsigned long long hi_tee_drv_mem_get_zone_range(int zone, unsigned long long *size);
void hi_tee_drv_mem_get_smmu_rw_err_range(unsigned long long *start, unsigned long long *size);
void hi_tee_drv_mem_get_smmu_pgtbl_range(unsigned long long *start, unsigned long long *size);

int hi_tee_drv_mem_is_nonsec(unsigned long long addr, unsigned long long size);
int hi_tee_drv_mem_is_sec(unsigned long long addr, unsigned long long size);
int hi_tee_drv_mem_is_secmmz(unsigned long long addr, unsigned long long size);
int hi_tee_drv_mem_config(void);

#endif /* __HI_TEE_DRV_MEM_LAYOUT_H */
