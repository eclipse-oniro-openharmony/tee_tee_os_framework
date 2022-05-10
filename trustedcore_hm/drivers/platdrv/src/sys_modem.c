/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file is temporary for modem, AP-CP Decoupling
 * Create: 2019-09-18
 */

#include "sys_modem.h"
#include <legacy_mem_ext.h>
#include <mem_ops.h>
#include "boot_sharedmem.h"
#include "sre_syscall.h"
#include "sre_task.h"
#include "tamgr_ext.h"
#include "ipclib.h"

#define DEFAULT_MID 0
#define DEFAULT_PT_NO 0

uint32_t sys_msg_send(uint32_t msg_hdl, uint32_t msg_id, uint32_t dst_pid, uint8_t channel_id)
{
    return ipc_msg_qsend(msg_hdl, msg_id, dst_pid, channel_id);
}

uint32_t sys_msg_receive(uint32_t *msg_hdl, uint32_t *msg_id, uint32_t *send_pid,
                         uint8_t channel_id, uint32_t timeout)
{
    return ipc_msg_q_recv(msg_hdl, msg_id, send_pid, channel_id, timeout);
}

uint32_t sys_get_share_mem_info(enum sharedmem_types type, uint32_t *buffer, uint32_t size)
{
    return get_shared_mem_info(type, buffer, size);
}

void *sys_mem_alloc(uint32_t size)
{
    return SRE_MemAlloc(DEFAULT_PT_NO, DEFAULT_MID, size);
}

uint32_t sys_mem_free(void *addr)
{
    return SRE_MemFree(DEFAULT_MID, addr);
}

uint32_t tee_get_task_id(uint32_t *task_id)
{
    uint32_t self;

    if (task_id == NULL)
        return OS_ERRNO_TSK_PTR_NULL;

    self = get_selfpid();
    if (self == SRE_PID_ERR)
        return OS_ERRNO_TSK_ID_INVALID;

    *task_id = self;

    return 0;
}
