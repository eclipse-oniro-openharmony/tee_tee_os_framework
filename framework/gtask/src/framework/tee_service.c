/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  Tee-service function declaration.
 * Author: yangjing  y00416812
 * Create: 2019-04-04
 */
#include "tee_service.h"
#include <limits.h>
#include <msg_ops.h>
#include <securec.h>
#include <stdlib.h>
#include <string.h>
#include "ta_framework.h"
#include "tee_internal_task_pub.h"
#include "tee_ss_agent_api.h"
#include "tee_task_exception.h"
#include "service_manager.h"

#define FAIL_RET    (-1)
#define SUCC_RET    0
#define ALREADY_RUN 1
#define NOT_RUN     0

static struct tee_srvc g_tee_srvc_configs[] = {
};

static const uint32_t g_tee_srvc_num = sizeof(g_tee_srvc_configs) / sizeof(g_tee_srvc_configs[0]);

bool is_dyn_service(const TEE_UUID *uuid)
{
    uint32_t i;
    struct tee_srvc *srvc = NULL;

    for (i = 0; i < g_tee_srvc_num; i++) {
        srvc = &g_tee_srvc_configs[i];
        if (memcmp(uuid, &srvc->uuid, sizeof(*uuid)) == 0)
            return true;
    }
    return false;
}

void init_tee_service()
{
    uint32_t i;
    struct dlist_node *temp = NULL;

    for (i = 0; i < g_tee_srvc_num; i++) {
        temp = (struct dlist_node *)malloc(sizeof(*temp));
        if (temp == NULL) {
            tloge("malloc list head fail, need notice!");
        } else {
            g_tee_srvc_configs[i].session_list = temp;
            dlist_init(g_tee_srvc_configs[i].session_list);
        }
    }
}

static void check_and_release_tee_srvc(struct tee_srvc *tee_service)
{
    TEE_Result ret;
    struct service_struct *temp_service = g_cur_service;
    struct session_struct *temp_session = g_cur_session;
    /* if session_list is not empty, don't need to release tee service */
    if (!dlist_empty(tee_service->session_list))
        return;

    if (tee_service->task_id == 0) {
        tlogi("task-id is 0, so no task to be released\n");
        return;
    }
    if (find_task(tee_service->task_id, &temp_service, &temp_session) == false) {
        tloge("fail to find info of tee service\n");
        return;
    }
    ret = process_close_session_entry(&temp_service, &temp_session);
    if (ret != TEE_SUCCESS)
        tloge("fail to close session of tee_srvc!\n");

    if (tee_service->unregister_task != NULL)
        tee_service->unregister_task();
    tee_service->task_id = 0;
    tee_service->is_loaded = false;
}

static int release_unbinded_session(const struct tee_srvc *tee_service, const struct session_struct *session)
{
    struct tee_srvc_session_node *entry = NULL;
    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;

    if (tee_service->session_list == NULL || session == NULL) {
        tloge("param is invalid!\n");
        return FAIL_RET;
    }

    dlist_for_each_safe(pos, next, tee_service->session_list) {
        entry = dlist_entry(pos, struct tee_srvc_session_node, service_head);
        if (entry->session == session &&
            entry->session->session_id == session->session_id) {
            if (session->session_status == TA_STATUS_SELF_DEAD) {
                entry->session = NULL; /* this entry will be removed when tui send unregister srvc response */
                tlogi("dead sess will be removed after!\n");
                return FAIL_RET;
            }
            if (entry->ref != 0)
                tlogi("session 0x%x to %s bind state ref %u remained!\n", session->task_id,
                    tee_service->name, entry->ref);
            dlist_delete(pos);
            free(entry);
            tlogi("session 0x%x is removed with %s\n", session->task_id, tee_service->name);
            return SUCC_RET;
        }
    }
    return FAIL_RET;
}

void del_remained_sess_node(const struct session_struct *session)
{
    uint32_t i;

    if (session == NULL) {
        tloge("session is NULL!\n");
        return;
    }

    /* this sess may call different tee srvc, so we run through all tee srvc */
    for (i = 0; i < g_tee_srvc_num; i++) {
    /*
     * when release session successfully, this session may be the last to call tee srvc,
     * so we need to check release tee srvc.
     */
        if (release_unbinded_session(&g_tee_srvc_configs[i], session) == SUCC_RET)
            check_and_release_tee_srvc(&g_tee_srvc_configs[i]);
    }
}

bool is_session_calling_dyn_srvc(uint32_t session_id)
{
    uint32_t i;
    struct tee_srvc_session_node *entry = NULL;
    struct dlist_node *pos = NULL;

    for (i = 0; i < g_tee_srvc_num; i++) {
        dlist_for_each(pos, g_tee_srvc_configs[i].session_list) {
            entry = dlist_entry(pos, struct tee_srvc_session_node, service_head);
            if (entry->session != NULL && entry->session->session_id == session_id)
                return true;
        }
    }
    return false;
}
