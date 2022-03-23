/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: tee_service function
 * Create: 2019-08-19
 */
#ifndef _TEE_COMMON_PUBLIC_SERVICE_H_
#define _TEE_COMMON_PUBLIC_SERVICE_H_

#include "tee_defines.h"
#include "tee_service_public.h"

typedef void (*tee_service_cmd_process)(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);

typedef struct {
    uint32_t cmd;
    tee_service_cmd_process fn;
} tee_service_cmd;

uint32_t tee_service_init();
void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp, uint32_t cmd);

void tee_common_task_entry(int init_build, const char *task_name);
TEE_Result tee_common_get_uuid_by_sender(uint32_t sender, TEE_UUID *uuid, uint32_t buffer_size);
void tee_unmap_from_task(uint32_t va_addr, uint32_t size);
int tee_map_from_task(uint32_t in_task_id, uint32_t va_addr, uint32_t size, uint32_t *virt_addr);
#endif
