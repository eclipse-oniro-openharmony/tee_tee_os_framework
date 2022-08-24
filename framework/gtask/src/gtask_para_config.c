/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: gtask config API
 * Create: 2020-09
 */

#include "gtask_para_config.h"
#include "tee_para.h"

uint32_t get_hashfile_max_size(void)
{
    return HASH_FILE_MAX_SIZE;
}

uint32_t get_mailbox_size(void)
{
    return MAILBOX_POOL_SIZE;
}

uint32_t get_res_mem_size(void)
{
    return RES_MEM_SIZE;
}
