/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: process load hifi
 * Create: 2018-5-21
 */

#ifndef __PROCESS_HIFI_INFO_H__
#define __PROCESS_HIFI_INFO_H__

#include <mem_page_ops.h>

UINT32 process_hifi_info_init(paddr_t soc_addr);
UINT32 process_hifi_info_fail(void);
UINT32 process_hifi_info_succ(void);
#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hifi_reset(UINT32 soc_type);
UINT32 hifi_set(UINT32 soc_type);
#endif

#endif /* __PROCESS_HIFI_INFO_H__ */

