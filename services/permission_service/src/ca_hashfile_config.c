/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: ca hashfile config
 * Author: liangshan
 * Create: 2022-04-14
 */

#include "ca_hashfile_config.h"
#include "tee_para.h"

uint32_t get_hashfile_max_size(void)
{
    return HASH_FILE_MAX_SIZE;
}
