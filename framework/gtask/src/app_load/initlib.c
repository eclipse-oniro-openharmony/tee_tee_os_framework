/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: init libs for gtask
 * Author: QiShuai  qishuai@huawei.com
 * Create: 2019-12-20
 */

#include <stddef.h>
#include <ta_framework.h>
#include <tee_internal_api.h>
#include <tee_log.h>
#include "gtask_config_hal.h"
#include "tee_config.h"
#include "gtask_inner.h"
#include "service_manager.h"
#include "gtask_core.h"


/*
 * CODEREVIEW CHECKLIST
 * ARG: passed from internal functions
 * RIGHTS: N/A
 * BUFOVF: N/A
 * INFOLEAK: N/A
 * RET: checked
 * RACING: N/A
 * RESLEAK: N/A
 * ARITHOVF: N/A
 * CODEREVIEW CHECKLIST by Yuan Pengfei <pf.yuan@huawei.com>
 */
void load_internal_task(const TEE_UUID *puuid)
{
    uint32_t num;
    uint32_t i;
    uint32_t ret;
    struct ta_property pty;
    const TEE_UUID *task_uuid = puuid;
    struct service_attr service_attr = { 0 };

    bool all_tasks = (puuid == LOAD_ALL_TASKS) ? true : false;

    num = get_builtin_task_nums();
    for (i = 0; i < num; i++) {
        const struct task_info_st *builtin_task_info = get_builtin_task_info_by_index(i);
        if (builtin_task_info == NULL)
            break;

        if (all_tasks == true)
            task_uuid = &builtin_task_info->uuid;
        else if (TEE_MemCompare(task_uuid, &builtin_task_info->uuid, sizeof(TEE_UUID)) != 0)
            continue;

        service_attr.build_in     = true;
        service_attr.ta_64bit     = builtin_task_info->ta_64bit;

        /* from loadELF_to_tee */
        ret = register_service(builtin_task_info->name, task_uuid, false, &service_attr);
        if (ret) {
            tloge("internal task register failed %s\n", builtin_task_info->name);
            continue;
        }
        ret = get_build_in_services_property(task_uuid, &pty);
        if (ret) {
            tloge("internal task get property failed %s\n", builtin_task_info->name);
            continue;
        }
        init_service_property(&pty.uuid, pty.stack_size, pty.heap_size, pty.single_instance, pty.multi_session,
                              pty.keep_alive, pty.ssa_enum_enable, false, (char *)pty.other_buff,
                              pty.other_len);
    }
}

void load_dynamic_service(const struct service_struct *dead_srv)
{
    struct service_attr service_attr = { 0 };

    if (dead_srv == NULL)
        return;

    service_attr.build_in     = false;
    service_attr.ta_64bit     = dead_srv->ta_64bit;
    service_attr.img_type     = dead_srv->img_type;

    /* from loadELF_to_tee */
    TEE_Result ret = register_service(dead_srv->name, &(dead_srv->property.uuid),
        dead_srv->is_dyn_conf_registed, &service_attr);
    if (ret != TEE_SUCCESS) {
        tloge("task register failed %s, ret:0x%x\n", dead_srv->name, ret);
        return;
    }

    init_service_property(&(dead_srv->property.uuid), dead_srv->property.stack_size,
        dead_srv->property.heap_size, dead_srv->property.single_instance, dead_srv->property.multi_session,
        dead_srv->property.keep_alive, dead_srv->property.ssa_enum_enable, false,
        dead_srv->property.other_buff, dead_srv->property.other_len);
}
