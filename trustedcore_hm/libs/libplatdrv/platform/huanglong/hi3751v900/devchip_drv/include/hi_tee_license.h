/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: interface of feature license in hisilicon chipset.
 */
#ifndef _HI_TEE_LICENSE_H_
#define _HI_TEE_LICENSE_H_

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cpluscplus */

typedef enum {
    HI_LICENSE_CPU_CAP = 0,
    HI_LICENSE_GPU_CAP,
    HI_LICENSE_DECODE_FORMAT,
    HI_LICENSE_DECODE_CAP,
    HI_LICENSE_NPU_CAP,
    HI_LICENSE_ENCODE_EN = 0x20,
    HI_LICENSE_ADSP_EN,
    HI_LICENSE_DISPLAY2_EN,
    HI_LICENSE_HDMI_RX_EN,
    HI_LICENSE_TSI_EN,
    HI_LICENSE_PCIE_EN,
    HI_LICENSE_SATA_EN,
    HI_LICENSE_USB3_EN,
    HI_LICENSE_MAX,
} hi_license_id;

hi_s32 hi_tee_drv_get_license_support(hi_license_id id, hi_u32 *value);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cpluscplus */

#endif /* _HI_TEE_LICENSE_H_ */
