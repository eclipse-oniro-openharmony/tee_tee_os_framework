/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hpp rom keyladder.
 * Author: Hisilicon security team
 * Create: 2019-03-13
 */
#include "hal_rkp.h"
#include "drv_rkp.h"
#include "drv_rkp_reg.h"
#include "drv_rkp_define.h"

#define  RKP_IRQ_NUMBER            (178 + 32)
#define  RKP_IRQ_NAME              "int_rkp_tee"

#define LOOP_MAX 1000 /* Waiting for logic completion count. */
#define DELEY_TIME 10 /* Delay time, xxx us. */

hi_u32  rkp_get_offset(hi_u32 addr)
{
    if ((addr - RKP_REG_BASE < 0x200) || (addr - RKP_REG_BASE > 0x600)) {
        return 0;
    }

    return RKP_TCPU_OFFSET;
}

static void _rkp_write_reg(const hi_u32 addr, const hi_u32 val)
{
    struct rkp_mgmt *mgmt = __get_rkp_mgmt();

    hi_info_klad("klad w 0x%08x 0x%08x\n", addr + rkp_get_offset(addr), val);
    reg_write((mgmt->io_base + (addr + rkp_get_offset(addr) - RKP_REG_BASE)), val);

    return;
}

static hi_u32 _rkp_read_reg(const hi_u32 addr)
{
    hi_u32 val;
    struct rkp_mgmt *mgmt = __get_rkp_mgmt();

    val = 0;
    reg_read((mgmt->io_base + (addr + rkp_get_offset(addr) - RKP_REG_BASE)), val);
    hi_info_klad("klad r 0x%08x 0x%08x\n", addr + rkp_get_offset(addr), val);
    return val;
}

static hi_u32 rkp_read_calc_start(void)
{
    rkp_calc_start_tee reg_v;
    reg_v.u32 = _rkp_read_reg(RKP_CALC_START);
    return reg_v.bits.tee_calc_start;
}


void rkp_write_reg(const hi_u32 addr, const hi_u32 val)
{
    _rkp_write_reg(addr, val);
    return;
}

hi_u32 rkp_read_reg(const hi_u32 addr)
{
    return _rkp_read_reg(addr);
}

hi_u32 rkp_is_idle(void)
{
    if (rkp_read_calc_start() == HI_FALSE) {
        return HI_SUCCESS;
    }
    return HI_FAILURE;
}

hi_s32 rkp_wait_idle(void)
{
#ifdef HI_INT_SUPPORT
    hi_s32 ret;
    struct rkp_mgmt *mgmt = __get_rkp_mgmt();

    mutex_lock(&mgmt->rkp_lock);

    ret = sem_wait(&mgmt->sem);

    mutex_unlock(&mgmt->rkp_lock);

    if (ret == -1) {
        hi_err_klad("rkp is busy, IRQ : %d, status : 0x%08x\n", RKP_IRQ_NUMBER, rkp_read_reg(RKP_ERROR_STATUS));
        return HI_ERR_KLAD_WAIT_TIMEOUT;
    }
#else
    hi_u32 time_out = LOOP_MAX;

    while (time_out--) {
        if (rkp_read_calc_start() == 0x0) {
            break;
        }
        udelay(DELEY_TIME);
    }
    if (time_out == 0) {
        hi_err_klad("rkp_wait_idle timeout!");
        return HI_FAILURE;
    }
#endif
    return HI_SUCCESS;
}

void rkp_slot_choose(hi_rkp_slot_choose slot)
{
    hi_u32 reg_slot_choose;

    rkp_slot_choose_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_SLOT_CHOOSE);
    tee_reg.bits.tee_slot_choose = slot;
    reg_slot_choose = tee_reg.u32;

    _rkp_write_reg(RKP_SLOT_CHOOSE, reg_slot_choose);
}

void rkp_klad_sel(hi_rkp_klad_sel klad_sel, hi_rkp_klad_type_sel klad_type_sel)
{
    hi_u32 reg_klad_choose;

    rkp_klad_choose_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_KLAD_CHOOSE);
    tee_reg.bits.tee_klad_sel = klad_sel;
    reg_klad_choose = tee_reg.u32;

    unused(klad_type_sel);
    _rkp_write_reg(RKP_KLAD_CHOOSE, reg_klad_choose);
}


void rkp_cas_kdf_static_disable(hi_rkp_cas_kdf_static_sel cas_kdf_static)
{
    hi_u32 reg_cas_kdf_disable;
    rkp_cas_kdf_static_disable_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_CAS_KDF_STATIC_DISABLE);
    tee_reg.bits.tee_cas_kdf_static_choose = cas_kdf_static;
    reg_cas_kdf_disable = tee_reg.u32;
    _rkp_write_reg(RKP_CAS_KDF_STATIC_DISABLE, reg_cas_kdf_disable);
}

void rkp_vendor_id(hi_u32 vendor_id)
{
    _rkp_write_reg(RKP_VENDOR_ID, vendor_id);
}

hi_s32 rkp_module_id(hi_u32 module_id3, hi_u32 module_id2, hi_u32 module_id1, hi_u32 module_id0)
{
    hi_u32 tmp;

    _rkp_write_reg(RKP_MODULE_ID_0, module_id0);
    _rkp_write_reg(RKP_MODULE_ID_1, module_id1);
    _rkp_write_reg(RKP_MODULE_ID_2, module_id2);
    _rkp_write_reg(RKP_MODULE_ID_3, module_id3);

    tmp = _rkp_read_reg(RKP_MODULE_ID_0);
    if (tmp != module_id0) {
        hi_err_klad("Invalid module id 0, w 0x%08x, r 0x%08x\n", module_id0, tmp);
        return HI_ERR_KLAD_RKP_INVALID_MODULE_ID;
    }
    tmp = _rkp_read_reg(RKP_MODULE_ID_1);
    if (tmp != module_id1) {
        hi_err_klad("Invalid module id 1, w 0x%08x, r 0x%08x\n", module_id1, tmp);
        return HI_ERR_KLAD_RKP_INVALID_MODULE_ID;
    }
    tmp = _rkp_read_reg(RKP_MODULE_ID_2);
    if (tmp != module_id2) {
        hi_err_klad("Invalid module id 2, w 0x%08x, r 0x%08x\n", module_id2, tmp);
        return HI_ERR_KLAD_RKP_INVALID_MODULE_ID;
    }
    tmp = _rkp_read_reg(RKP_MODULE_ID_3);
    if (tmp != module_id3) {
        hi_err_klad("Invalid module id 3, w 0x%08x, r 0x%08x\n", module_id3, tmp);
        return HI_ERR_KLAD_RKP_INVALID_MODULE_ID;
    }
    return HI_SUCCESS;
}

void rkp_unique_type(hi_u32 unique_type)
{
    hi_u32 reg_unique_type;

    rkp_unique_type_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_UNIQUE_TYPE);
    tee_reg.bits.tee_unique_type = unique_type;
    reg_unique_type = tee_reg.u32;

    _rkp_write_reg(RKP_UNIQUE_TYPE, reg_unique_type);
}

void rkp_fixed_rk_data(hi_u16 fixed_rk_data)
{
    hi_u32 reg_fixed_rk_data;

    rkp_fixed_rk_data_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_FIXED_RK_DATA);
    tee_reg.bits.tee_fixed_rk_data = fixed_rk_data;
    reg_fixed_rk_data = tee_reg.u32;

    _rkp_write_reg(RKP_FIXED_RK_DATA, reg_fixed_rk_data);
}

void rkp_fixed_rk_key(hi_u16 fixed_rk_key)
{
    hi_u32 reg_fixed_rk_key;

    rkp_fixed_rk_key_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_FIXED_RK_KEY);
    tee_reg.bits.tee_fixed_rk_key = fixed_rk_key;
    reg_fixed_rk_key = tee_reg.u32;

    _rkp_write_reg(RKP_FIXED_RK_KEY, reg_fixed_rk_key);
}

void rkp_fixed_rk_key_sel(hi_u16 fixed_rk_key_sel)
{
    hi_u32 reg_fixed_rk_key_sel;

    rkp_fixed_rk_key_sel_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_FIXED_RK_KEY_SEL);
    tee_reg.bits.tee_fixed_rk_key_sel = fixed_rk_key_sel;
    reg_fixed_rk_key_sel = tee_reg.u32;

    _rkp_write_reg(RKP_FIXED_RK_KEY_SEL, reg_fixed_rk_key_sel);
}

void rkp_calc_start(hi_rkp_command_type command_type)
{
    hi_u32 reg_calc_start;

    rkp_calc_start_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_CALC_START);
    tee_reg.bits.tee_command_type = command_type;
    tee_reg.bits.tee_calc_start = 1;
    reg_calc_start = tee_reg.u32;

    _rkp_write_reg(RKP_CALC_START, reg_calc_start);
}

hi_u32 rkp_read_int_enable(void)
{
    hi_u32 reg_int_enable;

    rkp_int_enable_tee tee_reg;
    tee_reg.u32 = _rkp_read_reg(RKP_INT_ENABLE);
    reg_int_enable = tee_reg.bits.tee_int_enable;

    return reg_int_enable;
}

hi_s32 rkp_check_error(void)
{
    hi_u32 reg;

    reg = _rkp_read_reg(RKP_DEBUG_INFO_3);
    if (reg != 0x01) {
        hi_err_klad("rkp debug info 3 = 0x%08x\n", reg);
        return HI_FAILURE;
    }
    reg = _rkp_read_reg(RKP_ROBUST_ALARM);
    if (reg != 0) {
        hi_err_klad("rkp robust alarm = 0x%08x\n", reg);
        return HI_FAILURE;
    }
    reg = _rkp_read_reg(RKP_ERROR_STATUS);
    if ((reg & 0xfffffffe) != 0) {
        hi_err_klad("rkp error status = 0x%08x\n", reg);
        return err_code_gen(RKP_ERR, reg);
    }
    return HI_SUCCESS;
}

hi_s32 rkp_get_klad_level(hi_u32 module_id_0)
{
    rkp_module_id_0 reg;

    reg.u32 = module_id_0;
    /* any cpu use the same bits. */
    return reg.tee.bits.tee_stage;
}

hi_void rkp_low_power_en(hi_void)
{
    rkp_low_power reg;

    reg.u32 = 0;
    reg.bits.rkp_low_power_enable = 0x05; /* low power enable */

    _rkp_write_reg(RKP_LOW_POWER, reg.u32);
}

#ifdef HI_INT_SUPPORT

static void _rkp_int_update(hi_u32 int_enable)
{
    hi_u32 reg_int_enable;

    rkp_int_enable_tee tee_reg;
    tee_reg.bits.tee_int_enable = int_enable;
    reg_int_enable = tee_reg.u32;

    _rkp_write_reg(RKP_INT_ENABLE, reg_int_enable);
    return;
}

hi_void rkp_int_en(hi_void)
{
    return _rkp_int_update(HI_TRUE);
}

hi_void rkp_int_dis(hi_void)
{
    return _rkp_int_update(HI_FALSE);
}

hi_void rkp_int_clr(hi_void)
{
    hi_u32 reg_raw_enable;

    rkp_raw_int_tee tee_reg;
    tee_reg.bits.tee_rkp_raw_int = HI_TRUE;
    reg_raw_enable = tee_reg.u32;

    _rkp_write_reg(RKP_RAW_INT, reg_raw_enable);
    return;
}

hi_u32 rkp_get_int_stat(hi_void)
{
    return _rkp_read_reg(RKP_INT_STATUS);
}

#endif

