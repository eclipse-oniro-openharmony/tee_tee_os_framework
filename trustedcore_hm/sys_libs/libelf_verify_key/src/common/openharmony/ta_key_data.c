/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee key data code
 * Author: Li Mingjuan limingjuan@huawei.com
 * Create: 2020.06.09
 */
#include <tee_defines.h>
#include <tee_log.h>
#include "ta_load_key.h"

bool is_wb_protecd_ta_key(void)
{
    return false;
}

TEE_Result get_ta_load_key(struct key_data *key)
{
    (void)key;

    tloge("not support TA encrypt\n");
    return TEE_ERROR_BAD_PARAMETERS;
}
