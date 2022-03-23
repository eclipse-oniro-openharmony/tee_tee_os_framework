/*
 * hisilicon ISP driver, hisp.h
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#ifndef _KIRIN_ISP_HISP_H_
#define _KIRIN_ISP_HISP_H_

#include "global_ddr_map.h"
#include "soc_acpu_baseaddr_interface.h"

#define CRG_BASE (SOC_ACPU_PERI_CRG_BASE_ADDR)
#define ISP_BASE (SOC_ACPU_ISP_Core_CFG_BASE_ADDR)
#define MEDIA_CRG_BASE_ADDR (SOC_ACPU_MEDIA1_CRG_BASE_ADDR)

#define CRG_0A4_PERRSTSTAT5                     (CRG_BASE + 0x0A4)
#define CRG_C80_PERIPHISP_SEC_RSTEN             (CRG_BASE + 0xC80)
#define CRG_C84_PERIPHISP_SEC_RSTDIS            (CRG_BASE + 0xC84)
#define CRG_C90_PERIPHISP_ISPA7_CTRL0           (CRG_BASE + 0xC90)

#define ISP_SUBCTRL_ISP_A7_CTRL_0               (SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR + 0x40)
#define ISP_SUBCTRL_ISP_A7_CTRL_1               (SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR + 0x44)
#define ISP_SUBCTRL_CANARY_ADDR                 (SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR + 0x6FC)
#define ISP_SUBCTRL_ISP_CPU_MID                 (SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR + 0x80C)

#define MEDIA_CRG_800_PERRSTEN_ISP_SEC          (MEDIA_CRG_BASE_ADDR + 0x800)
#define MEDIA_CRG_804_PERRSTDIS_ISP_SEC         (MEDIA_CRG_BASE_ADDR + 0x804)
#define MEDIA_CRG_808_PERRSTSTAT_ISP_SEC        (MEDIA_CRG_BASE_ADDR + 0x808)
#define MEDIA_CRG_810_ISPCPU_CTRL0_SEC          (MEDIA_CRG_BASE_ADDR + 0x810)

#define ISPA7_REMAP_ENABLE                      (1 << 31)
#define ISPA7_DBGPWRDUP                         (1 << 2)
#define ISPA7_VINITHI_HIGH                      (1 << 1)
#define ISPA7_REMAP_OFFSET                      (16)
#define ISPA7_REMAP_HADDR_OFFSET                32

#define ISPA7_NOSEC_IPC                         (1 << 2)

#define FAMA_REMAP_DISABLE                      (1 << 31)
#define IP_RST_MEDIA                            (3 << 17)
#define IP_RST_ISP                              (1)
#define ISP_CPU_MID                             (0x47)

#define ISPSS_CTRL_BASE_ADDR (ISP_BASE + 0x20000)
#define ISPSS_MODULE_CGR_HARDEN_SET_ADDR(base)      ((base) + (0x368UL))
#define ISPSS_MODULE_CGR_HARDEN_CLEAR_ADDR(base)    ((base) + (0x36CUL))
#define ISPSS_MODULE_RESET_HARDEN_SET_ADDR(base)    ((base) + (0x378UL))
#define ISPSS_MODULE_RESET_HARDEN_CLEAR_ADDR(base)  ((base) + (0x37CUL))

#define SMMU500_CB0_TTBR0_LOW_ADDR(base)            ((base) + (0x8020UL))
#define SMMU500_CB0_TTBR0_HIGH_ADDR(base)           ((base) + (0x8024UL))
#define SMMU500_CB0_TTBR1_LOW_ADDR(base)            ((base) + (0x8028UL))
#define SMMU500_CB0_TTBR1_HIGH_ADDR(base)           ((base) + (0x802CUL))
#define SMMU500_CB0_PAR_LOW_ADDR(base)              ((base) + (0x8050UL))
#define SMMU500_CB0_PAR_HIGH_ADDR(base)             ((base) + (0x8054UL))

#define SOC_ISP_1_ISP_CPU_7_MID                     (0x47)

#define SOC_PCTRL_PERI_STAT63_BIT_11                (11)
#define SOC_PCTRL_PERI_STAT63_BIT_12                (12)

#define ISP_CORE_SEC_CFG_CVDR_MID_SEC_ATTR_BIT      (2)
#define ISP_CORE_SEC_CFG_JPEGENC_SEC_ATTR_BIT       (1)
#define ISP_CORE_SEC_CFG_ISP_SEC_ATTR_BIT           (0)

#define ISP_SUBSYS_SEC_CFG_DPM_SEC_ATTR_BIT         (5)
#define ISP_SUBSYS_SEC_CFG_TCMDMA_SEC_ATTR_BIT      (4)
#define ISP_SUBSYS_SEC_CFG_SUB_CTRL_SEC_ATTR_BIT    (3)
#define ISP_SUBSYS_SEC_CFG_IPC_SEC_ATTR_BIT         (2)
#define ISP_SUBSYS_SEC_CFG_TIMER_SEC_ATTR_BIT       (1)
#define ISP_SUBSYS_SEC_CFG_WATCHDOG_SEC_ATTR_BIT    (0)

#define CGR_SRT                                     (0)
#define CGR_RT                                      (1)
#define CGR_CAP                                     (2)

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MIAMICW)
#define SEC_ISP_BIN_SIZE               HISI_RESERVED_SEC_CAMERA_PHYMEM_SIZE
#define SEC_ISP_IMG_BASE_ADDR          HISI_RESERVED_SEC_CAMERA_PHYMEM_BASE
#else
#define SEC_ISP_BIN_SIZE               0xFFFFFFFF
#define SEC_ISP_IMG_BASE_ADDR          0xFFFFFFFF
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define SEC_ISP_IMG_TEXT_BASE_ADDR     (SEC_ISP_IMG_BASE_ADDR)
#define SEC_ISP_IMG_TEXT_SIZE          (0x00600000)
#define SEC_ISP_IMG_DATA_BASE_ADDR     (SEC_ISP_IMG_TEXT_BASE_ADDR + SEC_ISP_IMG_TEXT_SIZE)
#define SEC_ISP_IMG_DATA_SIZE          (SEC_ISP_BIN_SIZE - SEC_ISP_IMG_TEXT_SIZE)
#define BBOX_MEM_BASE_ADDR             (0x2F100000)
#define BBOX_MEM_BASE_ADDR_SIZE        (0x860000)
#endif

#define SEC_CMA_IMAGE_SIZE             (SEC_ISP_BIN_SIZE)

#define ISP_DEBUG_ENABLE               (1 << 0)
#define ISP_WARRING_ENABLE             (1 << 1)
#define ISP_INFO_MASK                  (1 << 2)
#define ISP_ERR_MASK                   (1 << 3)

extern void uart_printf_func(const char *fmt, ...);

#define ISP_PRINT_FLAG \
    (ISP_ERR_MASK | ISP_WARRING_ENABLE | ISP_INFO_MASK)

#define ISP_ERR(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_ERR_MASK) { \
            uart_printf_func("[secisp][E]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_WARN(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_WARRING_ENABLE) {  \
            uart_printf_func("[secisp][W]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_INFO(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_INFO_MASK) {   \
            uart_printf_func("[secisp][I]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_DEBUG(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_DEBUG_ENABLE) { \
            uart_printf_func("[secisp][D]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

enum {
	SECISP_SUCCESS = 0,
	SECISP_FAIL,
	SECISP_BAD_PARA = 100,
	SECISP_TIMEOUT,
	SECISP_INVAILD_ADDR_MAP,
	SECISP_ERR_MAX,
};

#endif /* _KIRIN_ISP_HISP_H_ */

