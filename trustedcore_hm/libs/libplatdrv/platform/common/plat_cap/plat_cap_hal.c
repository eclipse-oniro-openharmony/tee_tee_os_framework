/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: oemkey adaptor implementation
 * Create: 2021-07-07
 */
#include <drv_module.h>
#include <list.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>
#include "oemkey_driver_hal.h"

struct oemkey_ops_list_t {
    uint32_t engine;
    const struct oemkey_ops_t *ops;
    struct list_head list;
};

static struct list_head g_oemkey_ops_head = LIST_HEAD_INIT(g_oemkey_ops_head);

static uint32_t get_provision_key(uint8_t *poemkey, size_t key_size)
{
    struct list_head *pos = NULL;
    struct oemkey_ops_list_t *oemkey_ops = NULL;
    uint32_t ret = OEMKEY_NOT_SUPPORTED;
    list_for_each(pos, &g_oemkey_ops_head) {
        oemkey_ops = list_entry(pos, struct oemkey_ops_list_t, list);
        if (oemkey_ops->engine != SEC_OEMKEY_FLAG)
            continue;
        bool check = (oemkey_ops->ops == NULL || oemkey_ops->ops->get_provision_key == NULL);
        if (check)
            break;
        ret = oemkey_ops->ops->get_provision_key(poemkey, key_size);
        break;
    }
    return ret;
}

int32_t register_oemkey_ops(uint32_t engine, const struct oemkey_ops_t *ops)
{
    struct oemkey_ops_list_t *tmp_ops = NULL;
    tmp_ops = malloc(sizeof(*tmp_ops));
    if (tmp_ops == NULL)
        return -1;
    tmp_ops->engine = engine;
    tmp_ops->ops = ops;
    list_add_tail(&(tmp_ops->list), &g_oemkey_ops_head);
    return 0;
}

int32_t platcap_hal_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_GET_PROVISION_KEY, permissions, CC_OEM_KEY_GROUP_PERMISSION)
        if (args[1] == 0 || args[0] == 0) {
            args[0] = -1;
            goto out;
        }
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        ret = get_provision_key((uint8_t *)(uintptr_t)args[0], args[1]);
        args[0] = ret;
        SYSCALL_END;
    default:
        return -1;
    }
    return 0;
}

DECLARE_TC_DRV(
    platcap_driver,
    0,
    0,
    0,
    TC_DRV_EARLY_INIT,
    NULL,
    NULL,
    platcap_hal_syscall,
    NULL,
    NULL
);
