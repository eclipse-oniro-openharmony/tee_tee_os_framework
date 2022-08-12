/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: register task to gtask
 * Create: 2022-01-15
 */

#include "task_register.h"
#include "task_dynamic_adaptor.h"

void register_task_huk_srv(void)
{
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
    TEE_UUID uuid = TEE_SERVICE_HUK;
    struct srv_adaptor_config_t config = {0};
    config.agent_id = 0;
    config.task_prio = TASK_PRIO_HUK_SERVICE;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, HUK_TASK_NAME, &config);
#endif
}

void register_multi_task(void)
{
    register_task_huk_srv();
}
