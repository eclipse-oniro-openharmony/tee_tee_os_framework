/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: hsm pg info get lib
* Author: chenyao
* Create: 2020/9/3
*/
#include "sre_syscalls_id_ext.h"
#include "hmdrv.h"

#include "syscall_api_common.h"
#include "hsm_pg_info_lib_api.h"

uint32_t lib_pg_info_read(uint32_t dev_id, uint32_t module, uint32_t data, uint64_t *out_data)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = dev_id;
    args[ARRAY_INDEX1] = module;
    args[ARRAY_INDEX2] = data;
    args[ARRAY_INDEX3] = (uint64_t)(uintptr_t)out_data;

    return hm_drv_call(SYSCALL_HSM_PG_GET, args, ARRAY_SIZE(args));
}
