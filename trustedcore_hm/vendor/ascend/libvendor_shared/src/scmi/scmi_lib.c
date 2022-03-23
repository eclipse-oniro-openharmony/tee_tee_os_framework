/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: scmi libs source file
* Author: huawei
* Create: 2019/1/14
*/
#include "sre_syscalls_id_ext.h"
#include "hmdrv.h"

#include "syscall_api_common.h"
#include "scmi_lib_api.h"

#define SCMI_SMEM_PADDR2VADDR_MAGIC 0x5A5A5A5A

uint32_t lib_scmi_channel_open(uint32_t dev_id, uint32_t channel)
{
    uint64_t args[ARRAY_INDEX2] = { 0 };

    args[ARRAY_INDEX0] = channel;
    args[ARRAY_INDEX1] = dev_id;

    return hm_drv_call(SYSCALL_SCMI_CHANNEL_OPEN, args, ARRAY_SIZE(args));
}

uint32_t lib_scmi_channel_close(uint32_t dev_id, uint32_t channel)
{
    uint64_t args[ARRAY_INDEX2] = { 0 };

    args[ARRAY_INDEX0] = channel;
    args[ARRAY_INDEX1] = dev_id;

    return hm_drv_call(SYSCALL_SCMI_CHANNEL_CLOSE, args, ARRAY_SIZE(args));
}

uint32_t lib_scmi_channel_send_data(uint32_t dev_id, uint32_t channel,
    uint8_t *buf, uint32_t len)
{
    uint64_t args[ARRAY_INDEX5] = {0};
    uint64_t buf_addr = (uint64_t)(uintptr_t)buf;

    args[ARRAY_INDEX0] = channel;
    args[ARRAY_INDEX1] = (uint64_t)upper_32_bits((uintptr_t)buf_addr);
    args[ARRAY_INDEX2] = (uint64_t)lower_32_bits((uintptr_t)buf_addr);
    args[ARRAY_INDEX3] = len;
    args[ARRAY_INDEX4] = dev_id;

    return hm_drv_call(SYSCALL_SCMI_CHANNEL_SEND_DATA, args, ARRAY_SIZE(args));
}

uint32_t lib_scmi_check_task_and_get_data(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len)
{
    uint64_t args[ARRAY_INDEX5] = {0};
    uint64_t buf_addr = (uint64_t)(uintptr_t)buf;

    args[ARRAY_INDEX0] = channel;
    args[ARRAY_INDEX1] = (uint64_t)upper_32_bits((uintptr_t)buf_addr);
    args[ARRAY_INDEX2] = (uint64_t)lower_32_bits((uintptr_t)buf_addr);
    args[ARRAY_INDEX3] = len;
    args[ARRAY_INDEX4] = dev_id;

    return hm_drv_call(SYSCALL_SCMI_CHANNEL_TASK_AND_GET_DATA, args, ARRAY_SIZE(args));
}

uint32_t lib_hiss_shared_paddr_to_vaddr(uint32_t dev_id, uint64_t *vaddr_out)
{
    uint64_t args[ARRAY_INDEX4] = {0};

    args[ARRAY_INDEX0] = SCMI_SMEM_PADDR2VADDR_MAGIC;
    args[ARRAY_INDEX1] = (uint64_t)lower_32_bits((uintptr_t)vaddr_out);
    args[ARRAY_INDEX2] = (uint64_t)upper_32_bits((uintptr_t)vaddr_out);
    args[ARRAY_INDEX3] = dev_id;

    return hm_drv_call(SYSCALL_SCMI_CHANNEL_PADDR2VADDR, args, ARRAY_SIZE(args));
}
