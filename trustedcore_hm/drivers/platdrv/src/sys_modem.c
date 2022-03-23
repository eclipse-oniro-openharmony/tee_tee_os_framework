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

#define DEFAULT_MID 0
#define DEFAULT_PT_NO 0

uint32_t sys_hwi_create(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode,
                        HWI_PROC_FUNC handler, uint32_t args)
{
    return SRE_HwiCreate(hwi_num, hwi_prio, mode, handler, args);
}

uint32_t sys_hwi_resume(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode)
{
    return SRE_HwiResume(hwi_num, hwi_prio, mode);
}

uint32_t sys_hwi_delete(uint32_t hwi_num)
{
    return SRE_HwiDelete(hwi_num);
}

uint32_t sys_hwi_disable(uint32_t hwi_num)
{
    return SRE_HwiDisable(hwi_num);
}

uint32_t sys_hwi_enable(uint32_t hwi_num)
{
    return SRE_HwiEnable(hwi_num);
}

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
    return __SRE_TaskSelf(task_id);
}
