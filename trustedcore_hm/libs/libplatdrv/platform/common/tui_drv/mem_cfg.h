/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secure memory interface for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-03-05
 */
#ifndef TASK_TUI_MEM_CFG_H
#define TASK_TUI_MEM_CFG_H

#include <stdint.h>

#include "tui_drv_types.h"

struct mem_cfg {
    /* in */
    uint32_t file_size;
    uint64_t phy_addr;
    uint32_t size;
    uint32_t npages;
    uint64_t info_length; /* page info num */
    bool need_clear;

    /* out */
    uint32_t vm_addr;
    int32_t drv_pid;
    uint32_t caller_pid;
    enum sec_mode mode;
};

#ifndef TEE_SUPPORT_M_DRIVER
#define T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT1  5
#define T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT2  6
#endif

void init_mem_cfg(struct mem_cfg *mem_cfg, const struct tui_config *cfg, bool need_clear);
bool set_secure_mem(struct mem_cfg *cfg, int32_t mem_type);
bool unset_secure_mem(struct mem_cfg *cfg, int32_t mem_type);
#endif /* TASK_TUI_MEM_CFG_H */
