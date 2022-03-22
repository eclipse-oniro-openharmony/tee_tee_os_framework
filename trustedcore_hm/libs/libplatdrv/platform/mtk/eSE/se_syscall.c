/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: set and get se channel information from platdrv
 * Author: earon.han@huawei.com
 * Create: 2020-1-14
 */
#include <errno.h>
#include <stdio.h>
#include <dlist.h>
#include <tee_bit_ops.h>
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_ext.h"
#include "sre_syscalls_id.h"
#include "drv_module.h"
#include "sre_access_control.h"
#include "drv_pal.h"
#include "drv_param_type.h"
#include "tee_mem_mgmt_api.h"
#include <hmdrv_stub.h> /* keep this last */

#define SE_SYSCALL_SUCCESS 0
#define SE_SYSCALL_ERROR   1
#define READER_MAX         4
#define CHANNEL_MAX        20
#define AID_LEN_MAX        16
#define SEAID_LIST_MAX     64

struct seaid_switch_info {
    uint8_t aid[AID_LEN_MAX];
    uint32_t aid_len;
    bool closed;
};

struct seaid_switch_sys_info {
    struct seaid_switch_info seaid_switch;
    struct dlist_node list;
};

struct se_connect_info {
    uint32_t sndr_pid;
    uint32_t connect_count;
    TEE_UUID uuid;
    struct dlist_node list;
};

static struct dlist_node g_se_connect_info_head[READER_MAX];
static uint32_t g_se_channel_info[READER_MAX][CHANNEL_MAX];
static uint32_t g_se_deactive_flag;
static struct dlist_node g_seaid_switch_head;
static uint32_t g_seaid_list_len;

static uint32_t set_se_channel_info(uint32_t reader_id, uint32_t channel_id, uint32_t task_id)
{
    if (reader_id >= READER_MAX || channel_id >= CHANNEL_MAX)
        return SE_SYSCALL_ERROR;
    g_se_channel_info[reader_id][channel_id] = task_id;
    return SE_SYSCALL_SUCCESS;
}

static uint32_t get_se_channel_info(uint32_t reader_id, uint32_t *task_id, uint32_t *cnt)
{
    uint32_t i;
    if (reader_id >= READER_MAX)
        return SE_SYSCALL_ERROR;
    if (task_id == NULL || cnt == NULL || *cnt < CHANNEL_MAX)
        return SE_SYSCALL_ERROR;

    for (i = 0; i < CHANNEL_MAX; i++)
        task_id[i] = g_se_channel_info[reader_id][i];
    *cnt = CHANNEL_MAX;

    return SE_SYSCALL_SUCCESS;
}

static uint32_t set_se_deactive(uint32_t deactive)
{
    g_se_deactive_flag = deactive;
    return SE_SYSCALL_SUCCESS;
}

static uint32_t get_se_deactive(uint32_t *deactive)
{
    if (deactive == NULL)
        return SE_SYSCALL_ERROR;
    *deactive = g_se_deactive_flag;
    return SE_SYSCALL_SUCCESS;
}

static uint32_t set_seaid_switch(struct seaid_switch_info *seaid_list, uint32_t seaid_list_len)
{
    uint32_t aid_index;
    struct seaid_switch_sys_info *seaid_switch_now = NULL;
    struct seaid_switch_sys_info *seaid_switch_tail = NULL;
    bool seaid_exist = false;

    if (seaid_list == NULL)
        return SE_SYSCALL_ERROR;

    for (aid_index = 0; aid_index < seaid_list_len; aid_index++) {
        seaid_exist = false;
        if (seaid_list[aid_index].aid_len > AID_LEN_MAX) {
            tloge("aid len is too long\n");
            continue;
        }
        dlist_for_each_entry(seaid_switch_now, &g_seaid_switch_head, struct seaid_switch_sys_info, list) {
            if (seaid_switch_now->seaid_switch.aid_len != seaid_list[aid_index].aid_len)
                continue;

            if (memcmp(seaid_switch_now->seaid_switch.aid, seaid_list[aid_index].aid,
                       seaid_list[aid_index].aid_len) != 0)
                continue;

            seaid_exist = true;
            break;
        }

        if (seaid_exist) {
            seaid_switch_tail = seaid_switch_now;
        } else {
            seaid_switch_tail = TEE_Malloc(sizeof(*seaid_switch_tail), 0);
            if (seaid_switch_tail == NULL) {
                tloge("malloc seaid switch failed\n");
                return SE_SYSCALL_ERROR;
            }
        }

        if (memcpy_s(seaid_switch_tail->seaid_switch.aid, AID_LEN_MAX,
                     seaid_list[aid_index].aid, seaid_list[aid_index].aid_len) != EOK) {
            if (!seaid_exist)
                TEE_Free(seaid_switch_tail);
            return SE_SYSCALL_ERROR;
        }
        seaid_switch_tail->seaid_switch.closed = seaid_list[aid_index].closed;
        seaid_switch_tail->seaid_switch.aid_len = seaid_list[aid_index].aid_len;

        if (!seaid_exist) {
            dlist_insert_tail(&seaid_switch_tail->list, &g_seaid_switch_head);
            g_seaid_list_len++;
        }
    }

    return SE_SYSCALL_SUCCESS;
}

static uint32_t get_seaid_list_len(uint32_t *seaid_list_len)
{
    if (seaid_list_len == NULL)
        return SE_SYSCALL_ERROR;

    *seaid_list_len = g_seaid_list_len;
    return SE_SYSCALL_SUCCESS;
}

static uint32_t get_seaid_switch(struct seaid_switch_info *seaid_list, uint32_t seaid_list_len)
{
    uint32_t aid_index = 0;
    struct seaid_switch_sys_info *seaid_switch_now = NULL;

    if (seaid_list == NULL || seaid_list_len != g_seaid_list_len)
        return SE_SYSCALL_ERROR;

    dlist_for_each_entry(seaid_switch_now, &g_seaid_switch_head, struct seaid_switch_sys_info, list) {
        if (aid_index >= seaid_list_len)
            return SE_SYSCALL_ERROR;
        if (memcpy_s(seaid_list[aid_index].aid, AID_LEN_MAX,
                     seaid_switch_now->seaid_switch.aid, seaid_switch_now->seaid_switch.aid_len) != EOK)
            return SE_SYSCALL_ERROR;

        seaid_list[aid_index].aid_len = seaid_switch_now->seaid_switch.aid_len;
        seaid_list[aid_index].closed = seaid_switch_now->seaid_switch.closed;
        aid_index++;
    }

    return SE_SYSCALL_SUCCESS;
}

static uint32_t set_se_connect_info(uint32_t reader_id,
    struct se_connect_info *se_connect_info_list, uint32_t se_connect_info_len)
{
    uint32_t i;
    struct se_connect_info *se_connect_info_temp = NULL;
    struct se_connect_info *se_connect_info_tail = NULL;
    bool info_exist = false;

    if (reader_id >= READER_MAX)
        return SE_SYSCALL_ERROR;

    for (i = 0; i < se_connect_info_len; i++) {
        info_exist = false;
        dlist_for_each_entry(se_connect_info_temp, &g_se_connect_info_head[reader_id], struct se_connect_info, list) {
            if (se_connect_info_temp->sndr_pid == se_connect_info_list[i].sndr_pid) {
                info_exist = true;
                break;
            }
        }

        if (se_connect_info_list[i].connect_count == 0) {
            if (info_exist) {
                dlist_delete((struct dlist_node *)&se_connect_info_temp->list);
                TEE_Free(se_connect_info_temp);
                se_connect_info_temp = NULL;
            }
            continue;
        }

        if (info_exist) {
            se_connect_info_tail = se_connect_info_temp;
        } else {
            se_connect_info_tail = TEE_Malloc(sizeof(*se_connect_info_tail), 0);
            if (se_connect_info_tail == NULL) {
                tloge("malloc se connect info failed\n");
                return SE_SYSCALL_ERROR;
            }
        }

        se_connect_info_tail->sndr_pid = se_connect_info_list[i].sndr_pid;
        se_connect_info_tail->connect_count = se_connect_info_list[i].connect_count;
        if (memcpy_s(&se_connect_info_tail->uuid, sizeof(se_connect_info_tail->uuid),
            &se_connect_info_list[i].uuid, sizeof(se_connect_info_list[i].uuid)) != EOK) {
            if (!info_exist)
                TEE_Free(se_connect_info_tail);
            return SE_SYSCALL_ERROR;
        }

        if (!info_exist)
            dlist_insert_tail(&se_connect_info_tail->list, &g_se_connect_info_head[reader_id]);
    }
    return TEE_SUCCESS;
}

static uint32_t get_se_connect_info(uint32_t reader_id,
    struct se_connect_info *se_connect_info_list, uint32_t *se_connect_info_len)
{
    uint32_t i = 0;
    struct se_connect_info *se_connect_info_temp = NULL;

    if (reader_id >= READER_MAX)
        return SE_SYSCALL_ERROR;

    dlist_for_each_entry(se_connect_info_temp, &g_se_connect_info_head[reader_id], struct se_connect_info, list) {
        if (i >= *se_connect_info_len)
            return SE_SYSCALL_ERROR;
        se_connect_info_list[i].sndr_pid = se_connect_info_temp->sndr_pid;
        se_connect_info_list[i].connect_count = se_connect_info_temp->connect_count;
        if (memcpy_s(&(se_connect_info_list[i].uuid), sizeof(se_connect_info_list[i].uuid),
            &(se_connect_info_temp->uuid), sizeof(se_connect_info_temp->uuid)) != EOK)
            return SE_SYSCALL_ERROR;
        i++;
    }
    *se_connect_info_len = i;

    return TEE_SUCCESS;
}

int se_status_driver_syscall(int swi_id, struct drv_param *params, uint64_t ullPermissions)
{
    uint64_t taskid_addr;
    uint64_t cnt_addr;
    uint64_t deactive_addr;
    uint64_t seaid_list_addr;
    uint64_t seaid_list_len_addr;

    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
    SYSCALL_PERMISSION(SW_SYSCALL_SE_CHANNELINFO_WRITE, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        if (args[0] > UINT32_MAX || args[1] > UINT32_MAX || args[2] > UINT32_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        args[0] = set_se_channel_info((uint32_t)args[0], (uint32_t)args[1], (uint32_t)args[2]);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SE_CHANNELINFO_READ, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        taskid_addr = args[0];
        cnt_addr = args[1];
        if (taskid_addr == 0 || cnt_addr == 0 || args[2] > UINT32_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(cnt_addr, sizeof(uint32_t));
        ACCESS_READ_RIGHT_CHECK(cnt_addr, sizeof(uint32_t));
        if (*((uint32_t *)(uintptr_t)cnt_addr) > CHANNEL_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(taskid_addr, (*(uint32_t *)(uintptr_t)cnt_addr) * sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(taskid_addr, (*(uint32_t *)(uintptr_t)cnt_addr) * sizeof(uint32_t));
        args[0] = get_se_channel_info((uint32_t)args[2],
            (uint32_t *)(uintptr_t)taskid_addr, (uint32_t *)(uintptr_t)cnt_addr);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SE_DEACTIVE_WRITE, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        if (args[0] > UINT32_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        args[0] = set_se_deactive((uint32_t)args[0]);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SE_DEACTIVE_READ, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        deactive_addr = args[0];
        if (deactive_addr == 0) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(deactive_addr, sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(deactive_addr, sizeof(uint32_t));
        args[0] = get_se_deactive((uint32_t *)(uintptr_t)deactive_addr);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEAID_SWITCH_WRITE, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        seaid_list_addr = args[0];
        if (seaid_list_addr == 0 || args[1] == 0 || args[1] > SEAID_LIST_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(seaid_list_addr, args[1] * sizeof(struct seaid_switch_info));
        ACCESS_READ_RIGHT_CHECK(seaid_list_addr, args[1] * sizeof(struct seaid_switch_info));
        args[0] = set_seaid_switch((struct seaid_switch_info *)(uintptr_t)seaid_list_addr, (uint32_t)args[1]);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEAID_LIST_LEN_READ, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        seaid_list_len_addr = args[0];
        if (seaid_list_len_addr == 0) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(seaid_list_len_addr, sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(seaid_list_len_addr, sizeof(uint32_t));
        args[0] = get_seaid_list_len((uint32_t *)(uintptr_t)seaid_list_len_addr);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SEAID_SWITCH_READ, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        seaid_list_addr = args[0];
        if (seaid_list_addr == 0 || args[1] == 0 || args[1] > SEAID_LIST_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(seaid_list_addr, args[1] * sizeof(struct seaid_switch_info));
        ACCESS_WRITE_RIGHT_CHECK(seaid_list_addr, args[1] * sizeof(struct seaid_switch_info));
        args[0] = get_seaid_switch((struct seaid_switch_info *)(uintptr_t)seaid_list_addr, (uint32_t)args[1]);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SE_CONNECT_INFO_WRITE, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        if (args[0] > UINT32_MAX || args[1] == 0 || args[2] > CHANNEL_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], args[2] * sizeof(struct se_connect_info));
        ACCESS_READ_RIGHT_CHECK(args[1], args[2] * sizeof(struct se_connect_info));
        args[0] = set_se_connect_info((uint32_t)args[0],
            (struct se_connect_info *)(uintptr_t)seaid_list_addr, (uint32_t)args[2]);
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_SE_CONNECT_INFO_READ, ullPermissions, SE_STATUS_GROUP_PERMISSION)
        if (args[0] > UINT32_MAX || args[1] == 0 || args[2] == 0) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[2], sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(uint32_t));
        if (*((uint32_t *)(uintptr_t)args[2]) > CHANNEL_MAX) {
            args[0] = SE_SYSCALL_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(args[1], *((uint32_t *)(uintptr_t)args[2]) * sizeof(struct se_connect_info));
        ACCESS_WRITE_RIGHT_CHECK(args[1], *((uint32_t *)(uintptr_t)args[2]) * sizeof(struct se_connect_info));
        args[0] = get_se_connect_info((uint32_t)args[0],
            (struct se_connect_info *)(uintptr_t)args[1], (uint32_t *)(uintptr_t)args[2]);
    SYSCALL_END
    default:
        return -1;
    }
    return 0;
}

static int se_syscall_init(void)
{
    uint32_t reader_id;

    dlist_init(&g_seaid_switch_head);
    for (reader_id = 0; reader_id < READER_MAX; reader_id++)
        dlist_init(&g_se_connect_info_head[reader_id]);

    return 0;
}

DECLARE_TC_DRV(
    se_status_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    se_syscall_init,
    NULL,
    se_status_driver_syscall,
    NULL,
    NULL
);
