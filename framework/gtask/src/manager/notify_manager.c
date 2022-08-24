/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TEE enviroment's notify manager of framework Implemention
 * Author: Zhangdeyao  zhangdeyao@huawei.com
 * Create: 2019-12-20
 */

#include <stddef.h>
#include <mem_ops_ext.h> // task_map_phy_mem && task_unmap
#include <mem_mode.h>    // non_secure
#include "tee_log.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "notify_manager.h"
#include "mem_manager.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "securec.h"

extern struct service_struct *g_cur_service;
extern struct session_struct *g_cur_session;

struct notify_data_struct *g_notify_data = NULL;

struct notify_data_struct *get_notify_data(void)
{
    return g_notify_data;
}

static bool g_notify_mem_registered = false;

int64_t teecall_register_notify_mem(uint64_t mem_addr);

static TEE_Result check_param_for_register_notify_memery(const smc_cmd_t *cmd, uint32_t *mem_size,
                                                         uint64_t *mem_addr)
{
    TEE_Param *params    = NULL;
    uint32_t param_types = 0;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_notify_mem_registered) {
        tloge("notify memory is already registered!\n");
        return TEE_ERROR_GENERIC;
    }
    g_notify_data = NULL;

    if (cmd_global_ns_get_params(cmd, &param_types, &params) != TEE_SUCCESS) {
        tloge("failed to map operation!\n");
        return TEE_ERROR_GENERIC;
    }

    /* check params types */
    if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* this condition should never happen here */
    if (params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *mem_size = params[1].value.a;
    if (*mem_size != NOTIFY_MEM_SIZE) {
        tloge("invalid notify mem size:%u\n", *mem_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* this will only be called once when booting up, the addr are trusted */
    if (task_map_phy_mem(0, params[0].value.a | ((paddr_t)params[0].value.b << SHIFT_OFFSET),
                         *mem_size, mem_addr, NON_SECURE)) {
        tloge("map notify data buffer error");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result register_notify_memery(const smc_cmd_t *cmd)
{
    uint64_t mem_addr = 0;
    uint32_t mem_size;

    TEE_Result ret = check_param_for_register_notify_memery(cmd, &mem_size, &mem_addr);
    if (ret != TEE_SUCCESS)
        return ret;

    /* will never reach there */
    if (mem_addr == 0)
        return TEE_ERROR_GENERIC;

    int64_t rc = teecall_register_notify_mem(mem_addr);
    if (rc != 0) {
        tloge("register notify mem failed: rc is %llx\n", rc);
        if (task_unmap(0, mem_addr, mem_size))
            tloge("task_unmap failed\n");

        return TEE_ERROR_BAD_PARAMETERS;
    }
    g_notify_data           = (void *)(uintptr_t)mem_addr;
    g_notify_mem_registered = true;
    return TEE_SUCCESS;
}
