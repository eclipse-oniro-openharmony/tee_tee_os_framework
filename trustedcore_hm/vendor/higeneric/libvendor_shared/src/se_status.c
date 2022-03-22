/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: set and get se channel information from platdrv
 * Create: 2020-1-14
 */
#include "se_status.h"
#include <hmdrv.h>
#include <hm_msg_type.h> /* for ARRAY_SIZE */

#include "tee_bit_ops.h"
#include "sre_syscalls_id.h"

__attribute__((visibility("default"))) \
void __sre_se_channel_info_write(uint32_t reader_id, uint32_t channel_id, uint32_t task_id)
{
    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)channel_id,
        (uint64_t)task_id,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_CHANNELINFO_WRITE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_se_channel_info_read(uint32_t reader_id, uint32_t *task_id, uint32_t *cnt)
{
    if (task_id == NULL || cnt == NULL || *cnt == 0)
        return;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)task_id,
        (uint64_t)(uintptr_t)cnt,
        (uint64_t)reader_id,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_CHANNELINFO_READ, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_se_deactive_write(uint32_t deactive)
{
    uint64_t args[] = {
        (uint64_t)deactive,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_DEACTIVE_WRITE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_se_deactive_read(uint32_t *deactive)
{
    if (deactive == NULL)
        return;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)deactive,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_DEACTIVE_READ, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_seaid_switch_write(uint8_t *seaid_list, uint32_t seaid_list_len)
{
    if (seaid_list == NULL || seaid_list_len == 0)
        return;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)seaid_list,
        (uint64_t)seaid_list_len,
    };
    (void)hm_drv_call(SW_SYSCALL_SEAID_SWITCH_WRITE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_seaid_list_len_read(uint32_t *seaid_list_len)
{
    if (seaid_list_len == NULL)
        return;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)seaid_list_len,
    };
    (void)hm_drv_call(SW_SYSCALL_SEAID_LIST_LEN_READ, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_seaid_switch_read(uint8_t *seaid_list, uint32_t seaid_list_len)
{
    if (seaid_list == NULL || seaid_list_len == 0)
        return;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)seaid_list,
        (uint64_t)seaid_list_len,
    };
    (void)hm_drv_call(SW_SYSCALL_SEAID_SWITCH_READ, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_se_connect_info_write(uint32_t reader_id, uint8_t *se_connect_info, uint32_t se_connect_info_len)
{
    if (se_connect_info == NULL || se_connect_info_len == 0)
        return;

    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)(uintptr_t)se_connect_info,
        (uint64_t)se_connect_info_len,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_CONNECT_INFO_WRITE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __sre_se_connect_info_read(uint32_t reader_id, uint8_t *se_connect_info, uint32_t *se_connect_info_len)
{
    if (se_connect_info == NULL || se_connect_info_len == NULL || *se_connect_info_len == 0)
        return;

    uint64_t args[] = {
        (uint64_t)reader_id,
        (uint64_t)(uintptr_t)se_connect_info,
        (uint64_t)(uintptr_t)se_connect_info_len,
    };
    (void)hm_drv_call(SW_SYSCALL_SE_CONNECT_INFO_READ, args, ARRAY_SIZE(args));
}
