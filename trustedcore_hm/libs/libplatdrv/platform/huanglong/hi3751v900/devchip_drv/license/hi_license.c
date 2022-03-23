/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implement for reading feature license in hisilicon chipset.
 */
#include "hi_tee_license.h"

#define GET_LICENSE_REG0        0x0084141c
#define GET_LICENSE_REG1        0x00841434
#define LICENSE0_ID_OFFSET      0x0
#define LICENSE1_ID_OFFSET      HI_LICENSE_ENCODE_EN
#define LICENSE_REG_SIZE        0x4
#define readl(addr)             (*(volatile hi_u32 *)(addr))

typedef union {
    struct {
        hi_u32 cpu_cap       : 4; /* [3:0]    */
        hi_u32 gpu_cap       : 4; /* [7:4]   */
        hi_u32 npu_cap       : 4; /* [11:8]  */
        hi_u32 decode_cap    : 4; /* [15:12] */
        hi_u32 decode_format : 8; /* [23:16] */
        hi_u32 reserved      : 8; /* [31:24] */
    } bits;
        hi_u32 u32;
    } hi_license0;

typedef union {
    struct {
        hi_u32 adsp_en      : 2;  /* [1:0]   */
        hi_u32 encode_en    : 1;  /* [2]     */
        hi_u32 display2_en  : 1;  /* [3]     */
        hi_u32 hdmi_rx_en   : 1;  /* [4]     */
        hi_u32 tsi_en       : 2;  /* [6:5]   */
        hi_u32 pcie_en      : 1;  /* [7]     */
        hi_u32 sata_en      : 1;  /* [8]     */
        hi_u32 usb3_en      : 1;  /* [9]     */
        hi_u32 reserved     : 22; /* [31:10] */
    } bits;
    hi_u32 u32;
} hi_license1;

static hi_s32 check_license0(hi_license_id id)
{
    hi_u32 *license0_addr = HI_NULL;
    hi_license0 license0;

    license0_addr = (hi_u32 *)GET_LICENSE_REG0;
    if (license0_addr == HI_NULL) {
        return -1;
    }
    license0.u32 = readl(license0_addr);
    switch (id) {
        case HI_LICENSE_CPU_CAP:
            return license0.bits.cpu_cap;
        case HI_LICENSE_GPU_CAP:
            return license0.bits.gpu_cap;
        case HI_LICENSE_DECODE_FORMAT:
            return license0.bits.decode_format;
        case HI_LICENSE_DECODE_CAP:
            return license0.bits.decode_cap;
        case HI_LICENSE_NPU_CAP:
            return license0.bits.npu_cap;
        default:
            return -1;
    }
    return -1;
}

static hi_s32 check_license1(hi_license_id id)
{
    hi_u32 *license1_addr = HI_NULL;
    hi_license1 license1;

    license1_addr = (hi_u32 *)GET_LICENSE_REG1;
    if (license1_addr == HI_NULL) {
        return -1;
    }
    license1.u32 = readl(license1_addr);
    switch (id) {
        case HI_LICENSE_ENCODE_EN:
            return license1.bits.encode_en;
        case HI_LICENSE_ADSP_EN:
            return license1.bits.adsp_en;
        case HI_LICENSE_DISPLAY2_EN:
            return license1.bits.display2_en;
        case HI_LICENSE_HDMI_RX_EN:
            return license1.bits.hdmi_rx_en;
        case HI_LICENSE_TSI_EN:
            return license1.bits.tsi_en;
        case HI_LICENSE_PCIE_EN:
            return license1.bits.pcie_en;
        case HI_LICENSE_SATA_EN:
            return license1.bits.sata_en;
        case HI_LICENSE_USB3_EN:
            return license1.bits.usb3_en;
        default:
            return -1;
    }
    return -1;
}

hi_s32 hi_tee_drv_get_license_support(hi_license_id id, hi_u32 *value)
{
    hi_s32 ret;

    if (id >= HI_LICENSE_MAX || value == HI_NULL) {
        return -1;
    }
    if (id < LICENSE1_ID_OFFSET) {
        ret = check_license0(id);
        if (ret < 0) {
            return -1;
        }
        *value = ret;
        return 0;
    } else {
        ret = check_license1(id);
        if (ret < 0) {
            return -1;
        }
        *value = ret;
        return 0;
    }

    return -1;
}
