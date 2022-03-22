/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2019. All rights reserved.
 * Description: 寄存器定义
 * Author: hsan
 * Create: 2015-11-19
 * History: 2015-11-19初稿完成
 *          2019-1-31 hsan code restyle
 */

#ifndef __HI_SDK_L0_REG_KDF_H__
#define __HI_SDK_L0_REG_KDF_H__

#define HI_SDK_L0_REG_KDF_BASE                                        (0x10110000)
#define HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0000)
#define HI_SDK_L0_REG_KDF_HISC_KDF_MODE_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0004)
#define HI_SDK_L0_REG_KDF_HISC_KDF_ITERATION_BASE                     (HI_SDK_L0_REG_KDF_BASE+0x0008)
#define HI_SDK_L0_REG_KDF_HISC_KDF_INT_ST_BASE                        (HI_SDK_L0_REG_KDF_BASE+0x000C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_INT_MASK_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0010)
#define HI_SDK_L0_REG_KDF_HISC_KDF_STATE_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x001C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK0_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0020)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK1_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0024)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK2_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0028)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK3_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x002C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK4_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0030)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK5_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0034)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK6_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x0038)
#define HI_SDK_L0_REG_KDF_HISC_KDF_PSK7_BASE                          (HI_SDK_L0_REG_KDF_BASE+0x003C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY0_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0040)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY1_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0044)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY2_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0048)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY3_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x004C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY4_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0050)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY5_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0054)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY6_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x0058)
#define HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY7_BASE                      (HI_SDK_L0_REG_KDF_BASE+0x005C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_SN0_BASE                           (HI_SDK_L0_REG_KDF_BASE+0x0060)
#define HI_SDK_L0_REG_KDF_HISC_KDF_SN1_BASE                           (HI_SDK_L0_REG_KDF_BASE+0x0064)
#define HI_SDK_L0_REG_KDF_HISC_KDF_SN2_BASE                           (HI_SDK_L0_REG_KDF_BASE+0x0068)
#define HI_SDK_L0_REG_KDF_HISC_KDF_SN3_BASE                           (HI_SDK_L0_REG_KDF_BASE+0x006C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT0_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0070)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT1_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0074)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT2_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0078)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT3_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x007C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT4_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0080)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT5_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0084)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT6_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x0088)
#define HI_SDK_L0_REG_KDF_HISC_KDF_RSLT7_BASE                         (HI_SDK_L0_REG_KDF_BASE+0x008C)
#define HI_SDK_L0_REG_KDF_HISC_KDF_VERSION_BASE                       (HI_SDK_L0_REG_KDF_BASE+0x0090)

struct hi_sdk_l0_reg_kdf_hisc_kdf_busy_s {
	hi_uint32 kdf_busy :1;
	hi_uint32 resv_0   :31;
};

struct hi_sdk_l0_reg_kdf_hisc_kdf_int_st_s {
	hi_uint32 kdf_int           : 1;
	hi_uint32 kdf_busy_wr_alarm : 1;
	hi_uint32 resv_0            : 30;
};

#endif