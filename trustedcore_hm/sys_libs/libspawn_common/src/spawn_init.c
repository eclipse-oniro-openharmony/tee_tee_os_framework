/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: init function used for set spawn environment
 * Create: 2021-07-13
 */

#include "spawn_init.h"
#include <stdint.h>
#include <stddef.h>
#include <securec.h>
#include <sys/types.h>
#include <ac_map.h>
#include <tee_log.h>

int32_t set_env_for_task(const struct env_param *param, const struct tee_uuid *uuid, struct env_base_buffer *env)
{
    if ((param == NULL) || (uuid == NULL) || (env == NULL)) {
        tloge("set env invalid param\n");
        return -1;
    }

    int32_t ret = snprintf_s(env->priority, sizeof(env->priority), sizeof(env->priority) - 1,
        "priority=%d", param->priority);
    if (ret < 0) {
        tloge("set priority:%d failed:0x%x\n", param->priority, ret);
        return -1;
    }

    uid_t uid;
    ret = ac_uuid_to_uid_sync(uuid, &uid);
    if (ret != 0) {
        if (ret != -ENOENT) {
            tloge("set drv cred failed\n");
            return -1;
        }
        uid = TA_DEFAULT_UID;
    }

    ret = snprintf_s(env->uid, sizeof(env->uid), sizeof(env->uid) - 1, "uid=%u", uid);
    if (ret < 0) {
        tloge("set uid:%u failed:0x%x\n", uid, ret);
        return -1;
    }

    ret = snprintf_s(env->ca, sizeof(env->ca), sizeof(env->ca) - 1, "ca=%u", param->ca);
    if (ret < 0) {
        tloge("set ca:%u failed:0x%x\n", param->ca, ret);
        return -1;
    }

    ret = snprintf_s(env->target_type, sizeof(env->target_type), sizeof(env->target_type) - 1,
        "target_type=%u", param->target_type);
    if (ret < 0) {
        tloge("set target type:%u failed:0x%x\n", param->target_type, ret);
        return -1;
    }

    return 0;
}

int32_t set_drv_env_for_task(const struct env_param *param, struct env_drv_base_buffer *env)
{
    if (param == NULL || env == NULL) {
        tloge("invalid drv param or env\n");
        return -1;
    }

    int32_t ret = snprintf_s(env->drv_index, sizeof(env->drv_index), sizeof(env->drv_index) - 1,
        "drv_index=%u", param->drv_index);
    if (ret < 0) {
        tloge("set drv index:%u failed:0x%x\n", param->drv_index, ret);
        return -1;
    }

    ret = snprintf_s(env->thread_limit, sizeof(env->thread_limit), sizeof(env->thread_limit) - 1,
        "thread_limit=%u", param->thread_limit);
    if (ret < 0) {
        tloge("set thread limit:%u failed:0x%x\n", param->thread_limit, ret);
        return -1;
    }

    ret = snprintf_s(env->stack_size, sizeof(env->stack_size), sizeof(env->stack_size) - 1,
        "stack_size=%u", param->stack_size);
    if (ret < 0) {
        tloge("set stack size:%u failed:0x%x\n", param->stack_size, ret);
        return -1;
    }

    return 0;
}
