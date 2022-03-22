/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:OTP driver in register level.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#include "hal_otp.h"


#include "drv_otp_define.h"
#include "tee_drv_ioctl_otp.h"
#include "drv_otp.h"
#include "hal_otp_reg.h"
#ifdef HI_OTP_TEST_SUPPORT
#include "drv_otp_proc.h"
#endif

#define LOOP_MAX 100000 /* Waiting for logic completion count. */
#define DELEY_TIME_CNT 10 /* Delay time, xxx us. */

/* static function */
static hi_void _otp_write_reg(hi_u32 addr, hi_u32 val)
{
    reg_write(addr, val);
    hi_info_otp("W 0x%x 0x%x\n", addr, val);
    return;
}

static hi_u32 _otp_read_reg(hi_u32 addr)
{
    hi_u32 val = 0;
    reg_read(addr, val);
    hi_info_otp("R 0x%x 0x%x\n", addr, val);
    return val;
}

static hi_s32 _otp_check_error_status(hi_void)
{
    otp_ctr_st0 st0;

    st0.u32 = _otp_read_reg(OTP_CTR_ST0);
    if (st0.bits.otp_init_rdy == 0) {
        print_err_code(HI_ERR_OTP_NOT_INITRDY);
        return HI_ERR_OTP_NOT_INITRDY;
    }
    if (st0.bits.err == 1) {
        print_warn_code(HI_ERR_OTP_PROG_PERM);
        return HI_ERR_OTP_PROG_PERM;
    }
    if (st0.bits.prm_rd_fail == 1) {
        print_err_code(HI_ERR_OTP_FAIL_PRMRD);
        return HI_ERR_OTP_FAIL_PRMRD;
    }
    if (st0.bits.rd_fail == 1) {
        print_err_code(HI_ERR_OTP_FAIL_RD);
        return HI_ERR_OTP_FAIL_RD;
    }
    if (st0.bits.prog_disable == 1) {
        print_err_code(HI_ERR_OTP_DISABLE_PROG);
        return HI_ERR_OTP_DISABLE_PROG;
    }
    return HI_SUCCESS;
}

static hi_s32 _otp_wait_ctrl_idle(hi_void)
{
    otp_rw_ctrl reg;
    hi_u32 cnt = 0;

    reg.u32 = _otp_read_reg(OTP_RW_CTRL);
    while ((reg.bits.start == HI_TRUE) && (cnt++ < LOOP_MAX)) {
        reg.u32 = _otp_read_reg(OTP_RW_CTRL);
        UDELAY(1);
    }
    if (cnt >= LOOP_MAX) {
        print_err_code(HI_ERR_OTP_TIMEOUT);
        return HI_ERR_OTP_TIMEOUT;
    }
    return HI_SUCCESS;
}

hi_s32 hal_otp_reset(hi_void)
{
    otp_ctr_st0 otp_ctr_st0;
    hi_u32 cnt = 0;

    otp_func_enter();
    _otp_write_reg(OTP_SH_UPDATE, 0x1); /* Shadow register update request.0:no request; 1:request */

    otp_ctr_st0.u32 = _otp_read_reg(OTP_CTR_ST0);
    while ((otp_ctr_st0.bits.soft_req_otp_rdy == HI_FALSE) && (cnt++ < LOOP_MAX)) {
        otp_ctr_st0.u32 = _otp_read_reg(OTP_CTR_ST0);
        UDELAY(1);
    }
    if (cnt >= LOOP_MAX) {
        print_err_code(HI_ERR_OTP_TIMEOUT);
        return HI_ERR_OTP_TIMEOUT;
    }
    otp_func_exit();
    return HI_SUCCESS;
}

hi_s32 hal_otp_read(hi_u32 addr, hi_u32 *value)
{
    hi_s32 ret;
    otp_rw_ctrl reg_ctr;
    struct time_us time;

    otp_timestamp(&time);

    /* ****** proc function begin ******* */
#ifdef HI_OTP_TEST_SUPPORT
    ret = fake_otp_virtual_read(addr, value);
    if (ret != HI_ERR_OTP_NON_FAKE_MODE) {
        return ret;
    }
#endif
    /* ****** proc function end   ******* */
    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    _otp_write_reg(OTP_RADDR, addr);

    reg_ctr.bits.wr_sel = OTP_OPT_READ;
    reg_ctr.bits.start = HI_TRUE;
    _otp_write_reg(OTP_RW_CTRL, reg_ctr.u32);

    ret = _otp_wait_ctrl_idle();
    if (ret != HI_SUCCESS) {
        print_err_func(_otp_wait_ctrl_idle, ret);
        return ret;
    }
    *value = _otp_read_reg(OTP_RDATA);
    otp_get_curr_cost("hal_read_word", &time);

    return _otp_check_error_status();
}

hi_s32 hal_otp_write(hi_u32 addr, hi_u32 value)
{
    hi_s32 ret;
    hi_u32 i;

    if (is_word_align(addr)) {
        print_err_hex2(addr, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    for (i = 0; i < WORD_SIZE; i++) {
        /* Only genarate 8 bits */
        ret = hal_otp_write_byte(addr + i, (value >> (BYTE_WIDTH * i)) & 0xff);
        if (ret != HI_SUCCESS) {
            print_err_hex3(addr + i, (value >> (BYTE_WIDTH * i)), ret);
            return ret;
        }
    }
    return HI_SUCCESS;
}

hi_s32 hal_otp_read_byte(hi_u32 addr, hi_u8 *value)
{
    hi_s32 ret;
    hi_u32 v = 0;

    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    ret = hal_otp_read(word_align(addr), &v);
    if (ret != HI_SUCCESS) {
        print_err_hex3(addr, v, ret);
        return ret;
    }
    *value = byte_den(v, addr);
    return HI_SUCCESS;
}

hi_s32 hal_otp_write_byte(hi_u32 addr, hi_u8 value)
{
    hi_s32 ret;
    otp_rw_ctrl reg_ctr;
    struct time_us time;

    otp_timestamp(&time);

    /* ****** proc function begin ******* */
#ifdef HI_OTP_TEST_SUPPORT
    ret = fake_otp_virtual_write_byte(addr, value);
    if (ret == HI_SUCCESS) {
        return ret;
    } else if (ret != HI_ERR_OTP_NON_FAKE_MODE) {
        print_err_func_hex3(fake_otp_virtual_write_byte, addr, value, ret);
        return ret;
    } else {
    }
#endif
    /* ****** proc function end   ******* */
    _otp_write_reg(OTP_WADDR, addr);
    _otp_write_reg(OTP_WDATA, value);

    _otp_write_reg(OTP_RW_CTRL, 0x5);
    reg_ctr.bits.wr_sel = OTP_OPT_WRITE;
    reg_ctr.bits.start = HI_TRUE;
    _otp_write_reg(OTP_RW_CTRL, reg_ctr.u32);

    ret = _otp_wait_ctrl_idle();
    if (ret != HI_SUCCESS) {
        print_err_func(_otp_wait_ctrl_idle, ret);
        return ret;
    }
    otp_get_curr_cost("hal_write_byte", &time);
    return _otp_check_error_status();
}

hi_s32 hal_otp_write_bit(hi_u32 addr, hi_u32 bit_pos)
{
    hi_s32 ret;
    hi_u8 data;

    if (bit_pos >= BYTE_WIDTH) {
        print_err_hex2(bit_pos, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    data = (1 << bit_pos);
    ret = hal_otp_write_byte(addr, data);
    if (ret != HI_SUCCESS) {
        print_err_hex3(addr, data, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 hal_otp_read_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 *value)
{
    hi_s32 ret;
    hi_u8 data = 0;

    if (start_bit + bit_width > BYTE_WIDTH) {
        print_err_hex3(start_bit, bit_width, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    ret = hal_otp_read_byte(addr, &data);
    if (ret != HI_SUCCESS) {
        print_err_hex3(addr, data, ret);
        return ret;
    }
    data &= gen_mask(start_bit + bit_width - 1, start_bit);
    *value = data >> start_bit;

    return HI_SUCCESS;
}

hi_s32 hal_otp_write_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 value)
{
    hi_s32 ret;
    hi_u8 data;

    if (start_bit + bit_width > BYTE_WIDTH) {
        print_err_code(HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    data = (value << start_bit) & gen_mask(start_bit + bit_width - 1, start_bit);
    ret = hal_otp_write_byte(addr, data);
    if (ret != HI_SUCCESS) {
        print_err_hex3(addr, data, ret);
        return ret;
    }
    return HI_SUCCESS;
}

