/*
*hisilicon ISP process, process_isp_info.h
*
*Copyright (c) 2013 Hisilicon Technologies Co., Ltd.
*
*/

#ifndef _PROCESS_ISP_INFO_H
#define _PROCESS_ISP_INFO_H

#include <mem_page_ops.h>

#ifdef CONFIG_HISI_ISP_SEC_IMAGE
UINT32 process_isp_info_init(paddr_t soc_addr);
UINT32 process_isp_info_fail(void);
UINT32 process_isp_info_succ(void);
#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hisi_isp_set_v2(UINT32 soc_type);
UINT32 hisi_isp_reset_v2(UINT32 soc_type);
#endif
#else
static inline UINT32 process_isp_info_init(__attribute__((unused)) paddr_t soc_addr) { return 0; }
static inline UINT32 process_isp_info_fail(void) { return 0; }
static inline UINT32 process_isp_info_succ(void) { return 0; }
#ifdef CONFIG_HISI_SECBOOT_IMG_V2
static inline UINT32 hisi_isp_set_v2(__attribute__((unused)) UINT32 soc_type) { return 0; }
static inline UINT32 hisi_isp_reset_v2(__attribute__((unused)) UINT32 soc_type) { return 0; }
#endif
#endif

#endif
