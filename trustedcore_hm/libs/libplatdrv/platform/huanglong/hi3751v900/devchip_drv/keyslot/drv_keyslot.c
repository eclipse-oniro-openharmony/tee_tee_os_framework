/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Key slot driver.Provide all the kernel API and ioctl API.
 * Author : Linux SDK team
 * Create: 2019/06/22
 */

#include "drv_keyslot.h"
#include "hal_keyslot.h"
#include "hi_tee_drv_keyslot.h"

/* structure definition */
typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_ioctl)(hi_void *arg, hi_u32 len);
} ks_ioctl_node;

static struct ks_mgmt g_ks_mgmt = {
    .io_base      = HI_NULL,
};

struct ks_mgmt *__get_ks_mgmt(hi_void)
{
    return &g_ks_mgmt;
}

static hi_s32 _drv_ks_unlock(const hi_keyslot_type slot_ind, const hi_u32 slot_num)
{
    if (slot_ind == HI_KEYSLOT_TYPE_TSCIPHER) {
        if (slot_num >= KS_TSCIPHER_SLOT_NUM) {
            return HI_ERR_KS_INVALID_PARAM;
        }
    } else if (slot_ind == HI_KEYSLOT_TYPE_MCIPHER) {
        if (slot_num >= KS_MCIPHER_SLOT_NUM) {
            return HI_ERR_KS_INVALID_PARAM;
        }
    } else {
        if (slot_num >= KS_HMAC_SLOT_NUM) {
            return HI_ERR_KS_INVALID_PARAM;
        }
    }
    return hal_ks_unlock(slot_ind, slot_num);
}

static hi_s32 _drv_ks_auto_lock(const hi_keyslot_type slot_ind, hi_u32 *slot_num)
{
    hi_u32 slot;
    hi_u32 start_slot = 0;

    if (slot_num == HI_NULL) {
        return HI_ERR_KS_PTR_NULL;
    }
    if (slot_ind >= HI_KEYSLOT_TYPE_MAX) {
        return HI_ERR_KS_INVALID_PARAM;
    }

    if (slot_ind == HI_KEYSLOT_TYPE_TSCIPHER) {
        slot = KS_TSCIPHER_SLOT_NUM;
    } else if (slot_ind == HI_KEYSLOT_TYPE_MCIPHER) {
        slot = KS_MCIPHER_SLOT_NUM;
    } else {
        start_slot = start_slot + KS_MCIPHER_SLOT_NUM;
        slot = KS_HMAC_SLOT_NUM;
    }

    for (start_slot = 0; start_slot < slot; start_slot++) {
        if (hal_ks_status(slot_ind, start_slot) != KS_STAT_UN_LOCK) {
            continue;
        }
        if (hal_ks_lock(slot_ind, start_slot) != HI_SUCCESS) {
            continue;
        }
        *slot_num = start_slot;
        return HI_SUCCESS;
    }
    return HI_ERR_KS_AUTO_LOCK_FAILED;
}

static hi_s32 _drv_ks_create(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    ks_entry *entry = (ks_entry *)arg;
    hi_u32 slot_num = 0;
    hi_keyslot_priv_attr keyslot_attr;

    if (arg == HI_NULL) {
        return HI_ERR_KS_PTR_NULL;
    }
    if (len != sizeof(ks_entry)) {
        print_err_hex2(len, sizeof(ks_entry));
        return HI_ERR_KS_INVALID_PARAM;
    }
    ret = _drv_ks_auto_lock(entry->ks_type, &slot_num);

    keyslot_attr.bits.type = entry->ks_type;
    keyslot_attr.bits.secure = 1; /* 1 means TEE, 0 means REE */

    if (ret != HI_SUCCESS) {
        print_err_func(_drv_ks_auto_lock, ret);
        return ret;
    }
    entry->ks_handle = id_2_handle(slot_num, keyslot_attr.u8);
    return HI_SUCCESS;
}

static hi_s32 _drv_ks_destory(hi_void *arg, hi_u32 len)
{
    ks_entry *entry = (ks_entry *)arg;
    hi_keyslot_priv_attr keyslot_attr;

    if (arg == HI_NULL) {
        return HI_ERR_KS_PTR_NULL;
    }
    if (len != sizeof(ks_entry)) {
        print_err_hex2(len, sizeof(ks_entry));
        return HI_ERR_KS_INVALID_PARAM;
    }
    if (is_invalid_handle(entry->ks_handle)) {
        print_err_hex(entry->ks_handle);
        return HI_ERR_KS_INVALID_PARAM;
    }
    keyslot_attr.u8 = handle_2_type(entry->ks_handle);
    return _drv_ks_unlock(keyslot_attr.bits.type, handle_2_id(entry->ks_handle));
}

hi_s32 drv_ks_init(hi_void)
{
    int ret;
    struct ks_mgmt *mgmt = __get_ks_mgmt();

    ret = mutex_init(&mgmt->lock);
    if (ret) {
        print_err_func(mutex_init, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_void _mutex_lock(hi_void)
{
    struct ks_mgmt *mgmt = __get_ks_mgmt();

    mutex_lock(&mgmt->lock);
}

hi_void _mutex_unlock(hi_void)
{
    struct ks_mgmt *mgmt = __get_ks_mgmt();

    mutex_unlock(&mgmt->lock);
}

static ks_ioctl_node g_ioctl_func_map[] = {
    { CMD_KS_CREATE,             _drv_ks_create },
    { CMD_KS_DESTORY,            _drv_ks_destory },
    { CMD_KS_MAX,                HI_NULL},
};

hi_s32 ks_ioctl_impl(unsigned int cmd, hi_void *arg, hi_u32 len)
{
    hi_s32 ret = HI_ERR_KS_IOCTL_CMD_INVALID;
    hi_u32 size;
    ks_ioctl_node *node = HI_NULL_PTR;

    _mutex_lock();

    for (size = 0, node = &g_ioctl_func_map[0];
        size < sizeof(g_ioctl_func_map) / sizeof(g_ioctl_func_map[0]);
        size++, node = &g_ioctl_func_map[size]) {
        if (node->cmd != cmd) {
            continue;
        }
        if (node->fun_ioctl != HI_NULL) {
            ret = node->fun_ioctl(arg, len);
        } else {
            ret = HI_ERR_KS_IOCTL_FUNC_NULL;
        }
        goto RET;
    }
RET:
    _mutex_unlock();
    return ret;
}

hi_s32 hi_drv_ks_create(const hi_keyslot_type slot_type, hi_handle *ks_handle)
{
    hi_s32 ret;
    hi_u32 slot_num = 0;

    _mutex_lock();

    ret = _drv_ks_auto_lock(slot_type, &slot_num);
    *ks_handle = id_2_handle(slot_num, slot_type);

    _mutex_unlock();
    return ret;
}

hi_s32 hi_drv_ks_destory(const hi_keyslot_type slot_type, const hi_handle ks_handle)
{
    hi_s32 ret;

    _mutex_lock();

    ret = _drv_ks_unlock(slot_type, handle_2_id(ks_handle));

    _mutex_unlock();
    return ret;
}

