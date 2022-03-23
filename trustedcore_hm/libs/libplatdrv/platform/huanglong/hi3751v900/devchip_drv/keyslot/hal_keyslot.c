/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:KS driver in register level.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#include "hal_keyslot.h"


#include "drv_keyslot_define.h"
#include "drv_keyslot.h"
#include "hal_keyslot_reg.h"

static hi_void _ks_write_reg(const hi_u32 addr, const hi_u32 val)
{
    reg_write(addr, val);
    hi_info_ks("ks w 0x%08x 0x%08x\n", addr, val);
    return;
}

static hi_u32 _ks_read_reg(const hi_u32 addr)
{
    hi_u32 val = 0;

    reg_read(addr, val);
    hi_info_ks("ks r 0x%08x 0x%08x\n", addr, val);
    return val;
}

static hi_u32 _ks_get_flush_status(void)
{
    return _ks_read_reg(KC_TEE_FLUSH_BUSY);
}

static hi_bool _ks_is_busy(void)
{
    /* bit 0 is 1 means there is a key slot flushed by the current cpu */
    return ((_ks_get_flush_status() & 0x1) != 0x0) ? HI_TRUE : HI_FALSE;
}

static hi_bool _ks_flush_failed(void)
{
    /* bit 1 is 1 means current cpu flush the target key slot due to time out */
    return ((_ks_get_flush_status() & 0x2) != 0x0) ? HI_TRUE : HI_FALSE;
}

#define LOOP_MAX 1000
#define DELAY_US 10

static hi_s32 _ks_flush_wait(void)
{
    hi_u32 time_out = LOOP_MAX;

    while (time_out--) {
        if (_ks_is_busy() == HI_FALSE) {
            break;
        }
        udelay(DELAY_US);
    }
    if (time_out == 0) {
        return HI_ERR_KS_STAT_TIME_OUT;
    }
    if (_ks_flush_failed()) {
        return HI_ERR_KS_FLUSH_TIME_OUT;
    }
    return HI_SUCCESS;
}

static hi_bool _ks_is_tscipher(const hi_keyslot_type slot_ind)
{
    if (slot_ind == HI_KEYSLOT_TYPE_TSCIPHER) {
        return HI_TRUE;
    } else {
        return HI_FALSE;
    }
}

ks_slot_stat hal_ks_status(const hi_keyslot_type slot_ind, const hi_u32 slot_num)
{
    kc_rd_lock_status stat;
    kc_rd_slot_num slot;

    slot.u32 = _ks_read_reg(KC_RD_SLOT_NUM);
    slot.bits.tscipher_slot_ind = _ks_is_tscipher(slot_ind);
    slot.bits.slot_num_cfg = slot_num;
    _ks_write_reg(KC_RD_SLOT_NUM, slot.u32);

    stat.u32 = _ks_read_reg(KC_RD_LOCK_STATUS);
    return (ks_slot_stat)stat.bits.rd_lock_status;
}

hi_s32 hal_ks_lock(const hi_keyslot_type slot_ind, const hi_u32 slot_num)
{
    ks_slot_stat state;

    kc_tee_lock_cmd tee_reg;
    if (_ks_is_busy()) {
        return HI_ERR_KS_BUSY;
    }
    tee_reg.u32 = _ks_read_reg(KC_TEE_LOCK_CMD);
    tee_reg.bits.tee_lock_cmd = 1;
    tee_reg.bits.tpp_key_enable = 1;
    tee_reg.bits.tee_tscipher_ind = _ks_is_tscipher(slot_ind);
    tee_reg.bits.tee_key_slot_num = slot_num;
    _ks_write_reg(KC_TEE_LOCK_CMD, tee_reg.u32);

    state = hal_ks_status(slot_ind, slot_num);
    if (state != KS_STAT_TEE_LOCK) {
        return HI_ERR_KS_LOCKED_CPUX + state;
    }
    return HI_SUCCESS;
}

hi_s32 hal_ks_unlock(const hi_keyslot_type slot_ind, const hi_u32 slot_num)
{
    kc_tee_lock_cmd tee_reg;
    if (_ks_is_busy()) {
        return HI_ERR_KS_BUSY;
    }
    tee_reg.u32 = _ks_read_reg(KC_TEE_LOCK_CMD);
    tee_reg.bits.tee_lock_cmd = 0;
    tee_reg.bits.tee_tscipher_ind = _ks_is_tscipher(slot_ind);
    tee_reg.bits.tee_key_slot_num = slot_num;
    _ks_write_reg(KC_TEE_LOCK_CMD, tee_reg.u32);
    return _ks_flush_wait();
}

