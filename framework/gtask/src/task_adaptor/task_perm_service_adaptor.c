/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: interfaces for gtask to communicate with perm service
 * Author: l00238133
 * Create: 2019-10-28
 */

#include "task_perm_service_adaptor.h"
#include "task_adaptor.h"
#include "permsrv_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "tee_app_load_srv.h"

#define TASK_PRIO_PERM_SERVICE (DEFAULT_TASK_PRIO - 2)
void register_task_perm_serv(void);

static void register_ta_to_perm_serv(const struct reg_ta_info *reg_msg, uint32_t perm_task_id)
{
    (void)perm_task_id;
    tee_ext_register_ta(&(reg_msg->uuid), reg_msg->taskid, reg_msg->userid);
}

static void unregister_ta_to_perm_serv(const char *cur_task_name, const struct reg_ta_info *reg_msg,
    uint32_t perm_task_id)
{
    (void)perm_task_id;
    (void)cur_task_name;
    tee_ext_unregister_ta(&(reg_msg->uuid), reg_msg->taskid, reg_msg->userid);
}

static void send_ta_release_msg_to_perm_serv(const char *cur_task_name, const struct reg_ta_info *msg,
    uint32_t perm_task_id)
{
    (void)cur_task_name;
    (void)perm_task_id;
    tee_ext_notify_unload_ta(&(msg->uuid));
}

static void task_perm_serv_crash_callback(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *config)
{
    (void)uuid;
    (void)task_name;
    (void)config;
    elf_verify_crash_callback();
    register_task_perm_serv();
}

static void task_perm_serv_init_priv_info(struct task_adaptor_info *task)
{
    task->task_crash_callback   = task_perm_serv_crash_callback;
    task->register_ta_to_task   = register_ta_to_perm_serv;
    task->unregister_ta_to_task = unregister_ta_to_perm_serv;
    task->send_ta_release_msg_to_task = send_ta_release_msg_to_perm_serv;
}

/* perm service is enabled by default */
void register_task_perm_serv(void)
{
    TEE_UUID uuid = TEE_SERVICE_PERM;

    struct task_adaptor_info *task =
        register_task_proc(&uuid, TASK_PRIO_PERM_SERVICE, PERM_SERVICE_NAME, task_perm_serv_init_priv_info, NULL);
    if (task == NULL)
        tlogd("jump to reg task perm serv\n");
}
