/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dynion driver func
 * Author: Heyanhong heyanhong2@huawei.com
 * Create: 2020-09-07
 */
#ifndef PLATDRV_DYNION_CONFIG_H
#define PLATDRV_DYNION_CONFIG_H
#include "dynion.h"      /* struct sglist */

#define SEC_FEATURE_OFFSET 8
#define DDR_CFG_TYPE_BITS  0xFF
#define MAX_PAGE_NUM 131072 /* 512M */

#define SECURE_MEM_ENABLE 1 /* set mem to secure */
#define SECURE_MEM_DISABLE 0 /* set mem to nosecure */
#define SECMEM_SVC_ID 1 /* ignored in secmem.c */

enum DDR_CFG_TYPE {
    DDR_SET_SEC,
    DDR_UNSET_SEC,
};

int32_t get_dynmem_addr(struct sglist *sglist, int32_t type, uint64_t *paddr, uint32_t *psize);

int32_t set_dynmem_config(struct sglist *sglist, int32_t type);

#endif
