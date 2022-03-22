/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Describe the basic functions of this file
 * Create: 2019-09-18
 */

#ifndef PLATDRV_SYS_MODEM_H
#define PLATDRV_SYS_MODEM_H

#include <sre_hwi.h>
#include <msg_ops.h>
#include <boot_sharedmem.h>

uint32_t sys_hwi_resume(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode);
uint32_t sys_hwi_enable(uint32_t hwi_num);
uint32_t sys_hwi_disable(uint32_t hwi_num);
uint32_t sys_hwi_create(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode, HWI_PROC_FUNC handler, uint32_t args);
uint32_t sys_hwi_delete(uint32_t hwi_num);

uint32_t sys_msg_send(uint32_t msg_hdl, uint32_t msg_id, uint32_t dst_pid, uint8_t channel_id);
uint32_t sys_msg_receive(uint32_t *msg_hdl, uint32_t *msg_id, uint32_t *send_pid,
                         uint8_t channel_id, uint32_t timeout);
uint32_t sys_get_share_mem_info(enum sharedmem_types type, uint32_t *buffer, uint32_t size);
void *sys_mem_alloc(uint32_t size);
uint32_t sys_mem_free(void *addr);
uint32_t tee_get_task_id(uint32_t *task_id);

#endif /* PLATDRV_SYS_MODEM_H */
