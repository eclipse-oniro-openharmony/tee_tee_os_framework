/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: old header reserved for modem
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-06-11
 */
#ifndef LIBSEC_MODEM_OLD_HEADER_SRE_SECUREMMU_H
#define LIBSEC_MODEM_OLD_HEADER_SRE_SECUREMMU_H
#include <stdint.h>
#include <list.h>
#include "sre_base.h"
#include "sre_arm_mmu.h"
#include "sre_task.h"
#include "mem_mode.h"
#include "drv_mem.h"
#include "ccmgr_ops_ext.h" /* CRYS_RND_GenerateVector */
#include "drv_cache_flush.h"

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

#endif
