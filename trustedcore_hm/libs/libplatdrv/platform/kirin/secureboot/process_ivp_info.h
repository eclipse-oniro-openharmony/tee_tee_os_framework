/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file just declare some api
 * Create: 2019-05-24
 */

#ifndef _PROCESS_IVP_INFO_H_
#define _PROCESS_IVP_INFO_H_

#include <mem_page_ops.h>

UINT32 process_ivp_info_init(paddr_t soc_addr);
UINT32 process_ivp_info_fail(void);
UINT32 process_ivp_info_succ(void);
#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hisi_ivp_set(UINT32 soc_type);
UINT32 hisi_ivp_reset(UINT32 soc_type);
#endif

#endif /* _PROCESS_IVP_INFO_H_ */
