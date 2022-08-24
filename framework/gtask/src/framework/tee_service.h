/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  Tee-service function declaration.
 * Author: yangjing  y00416812
 * Create: 2019-04-18
 */

#ifndef __TEE_SERVICE_H_
#define __TEE_SERVICE_H_
#include <dlist.h>
#include "tee_load_lib.h"
#include "ta_framework.h"

#define FROM_REE 1
#define FROM_TEE 0

typedef TEE_Result (*register_task_f)(uint32_t *task_id);
typedef void (*unregister_task_f)();

struct tee_srvc {
    TEE_UUID uuid;
    char *name;
    int elf_type; // 0-from tee, 1-from ree
    uint32_t task_id;
    bool is_loaded;
    struct dlist_node *session_list;
    register_task_f register_task;
    unregister_task_f unregister_task;
};

struct tee_srvc_session_node {
    struct session_struct *session;
    struct dlist_node service_head;
    uint32_t ref;
};

void init_tee_service();
void del_remained_sess_node(const struct session_struct *session);
bool is_session_calling_dyn_srvc(uint32_t session_id);
bool is_dyn_service(const TEE_UUID *uuid);
#endif
