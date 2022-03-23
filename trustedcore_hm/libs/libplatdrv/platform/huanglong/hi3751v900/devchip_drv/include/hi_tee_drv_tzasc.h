/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tzasc api
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef _HI_TEE_DRV_TZASC_H_
#define _HI_TEE_DRV_TZASC_H_

typedef struct {
    int en;
    unsigned long long base;
    unsigned long long size;
    unsigned int sp;
    unsigned int mid_en;
    unsigned long long mid_w;
    unsigned long long mid_r;
} hi_tee_tzasc_region;

typedef struct {
    int en;
    unsigned long long base;
    unsigned long long size;
    unsigned long long master_type0;
} hi_tee_tzasc_share_region;

#define HI_TEE_TZASC_RIGHT_NONE          0x5a
#define HI_TEE_TZASC_RIGHT_NON_SEC       0xa5
#define HI_TEE_TZASC_RIGHT_SEC           0x8a
#define HI_TEE_TZASC_RIGHT_FULL          0xa8

void hi_tee_drv_tzasc_init(void);
void hi_tee_drv_tzasc_enable(void);
void hi_tee_drv_tzasc_disable(void);
void hi_tee_drv_tzasc_config_res_region(unsigned int sp, unsigned long long mid);
void hi_tee_drv_tzasc_add_sec_region(hi_tee_tzasc_region *region);
void hi_tee_drv_tzasc_add_share_region(hi_tee_tzasc_share_region *region);
void hi_tee_drv_tzasc_share_release_config(const unsigned int en, unsigned long long mid);
void hi_tee_drv_tzasc_config_tzpc(void);
void hi_tee_drv_tzasc_security_check(void);
void hi_tee_drv_tzasc_get_share_region_end(unsigned long long *addr);
#endif /* _HI_TEE_DRV_TZASC_H_ */
