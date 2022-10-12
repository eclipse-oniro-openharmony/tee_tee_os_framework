/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee dynamic service function
 * Create: 2022-01-15
 */
#ifndef _TEE_DYNAMIC_SRV_H_
#define _TEE_DYNAMIC_SRV_H_

#include <pthread.h>
#include "tee_service_public.h"

struct srv_thread_init_info {
    void *(*func)(void *arg);
    uint32_t max_thread;
    int32_t shadow;
    uint32_t stack_size;
    uint32_t time_out_sec;
};

typedef void (*srv_dispatch_fn_t)(tee_service_ipc_msg *msg,
    uint32_t sndr, tee_service_ipc_msg_rsp *rsp);

struct srv_dispatch_t {
    uint32_t cmd;
    srv_dispatch_fn_t fn;
};

TEE_Result tee_srv_get_uuid_by_sender(uint32_t sender, TEE_UUID *uuid);
void tee_srv_unmap_from_task(uint32_t va_addr, uint32_t size);
int tee_srv_map_from_task(uint32_t in_task_id, uint32_t va_addr, uint32_t size, uint32_t *virt_addr);
void tee_srv_cs_server_loop(const char *task_name, const struct srv_dispatch_t *dispatch,
    uint32_t n_dispatch, struct srv_thread_init_info *cur_thread);
#endif
