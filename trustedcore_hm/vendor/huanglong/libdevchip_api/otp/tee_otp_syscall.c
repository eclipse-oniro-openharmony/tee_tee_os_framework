/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Defines the interface for calling the OTP read/write method.
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */

#include "tee_otp_syscall.h"

#include "tee_otp_define.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_ioctl_otp.h"

static hi_s32 __ks_ioctl(hi_u32 cmd, const hi_void *data)
{
    hi_u32 val;
    hi_s32 ret = HI_SUCCESS;

    hi_u32 args[] = {
        (hi_u32)cmd,
        (hi_u32)(uintptr_t)data,
    };

    val = hm_drv_call(CMD_OTP_PROCESS, args, ARRAY_SIZE(args));
    if (val != HI_SUCCESS) {
        print_err_hex4(ARRAY_SIZE(args), cmd, (hi_u32)(uintptr_t)data, ret);
        ret = HI_FAILURE;
    }
    return ret;
}

hi_s32 otp_syscall_read(hi_u32 addr, hi_u32 *value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    if (addr > 0xffc) { /* range: 1k. */
        print_err_hex2(HI_ERR_OTP_INVALID_PARA, addr);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    ret = __ks_ioctl(CMD_OTP_READ, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_OTP_READ, entry.addr, ret);
        return ret;
    }
    *value = entry.value;

    return HI_SUCCESS;
}

hi_s32 otp_syscall_read_byte(hi_u32 addr, hi_u8 *value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    if (addr >= 0x1000) { /* range: 1k. */
        print_err_hex2(HI_ERR_OTP_INVALID_PARA, addr);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    ret = __ks_ioctl(CMD_OTP_READ_BYTE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex3(CMD_OTP_READ_BYTE, entry.addr, ret);
        return ret;
    }
    *value = (hi_u8)entry.value;

    return HI_SUCCESS;
}

hi_s32 otp_syscall_write(hi_u32 addr, hi_u32 value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    if (addr > 0xffc) { /* range: 1k. */
        print_err_hex2(HI_ERR_OTP_INVALID_PARA, addr);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    entry.value = value;
    ret = __ks_ioctl(CMD_OTP_WRITE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex4(CMD_OTP_WRITE, entry.addr, entry.value, ret);
        return ret;
    }
    return HI_SUCCESS;
}


hi_s32 otp_syscall_write_byte(hi_u32 addr, hi_u8 value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if (addr > 0xffc) { /* range: 1k. */
        print_err_hex2(HI_ERR_OTP_INVALID_PARA, addr);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    entry.value = (hi_u32)value;
    ret = __ks_ioctl(CMD_OTP_WRITE_BYTE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex4(CMD_OTP_WRITE_BYTE, entry.addr, entry.value, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_syscall_read_bits_one_byte(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_u8 *value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if (value == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }
    if ((addr > 0xfff) || (start_bit + bit_width > 0x08)) { /* range: 1k. */
        print_err_hex4(HI_ERR_OTP_INVALID_PARA, addr, start_bit, bit_width);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    entry.value = otp_get_para(start_bit, bit_width, 0);

    ret = __ks_ioctl(CMD_OTP_READ_BITS_ONEBYTE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex4(CMD_OTP_READ_BITS_ONEBYTE, entry.addr, entry.value, ret);
        return ret;
    }
    *value = otp_value_byte(entry.value);
    return HI_SUCCESS;
}


hi_s32 otp_syscall_write_bits_one_byte(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_u8 value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if ((addr > 0xfff) || (start_bit + bit_width > 0x08)) { /* range: 1k. */
        print_err_hex4(HI_ERR_OTP_INVALID_PARA, addr, start_bit, bit_width);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    entry.value = otp_get_para(start_bit, bit_width, value);

    ret = __ks_ioctl(CMD_OTP_WRITE_BITS_ONEBYTE, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex4(CMD_OTP_WRITE_BITS_ONEBYTE, entry.addr, entry.value, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_syscall_write_bit(hi_u32 addr, hi_u8 bit_pos, hi_u8 bit_value)
{
    hi_s32 ret;
    otp_entry entry = {0};

    if ((addr > 0xfff) || (bit_pos >= 0x8) || (bit_value > 1)) { /* range: 1k. */
        print_err_hex4(HI_ERR_OTP_INVALID_PARA, addr, bit_pos, bit_value);
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry.addr = addr;
    entry.value = otp_get_para(bit_pos, 1, bit_value);

    ret = __ks_ioctl(CMD_OTP_WRITE_BIT, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex4(CMD_OTP_WRITE_BIT, entry.addr, entry.value, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_syscall_reset(hi_void)
{
    hi_s32 ret;
    otp_entry entry = {0};

    ret = __ks_ioctl(CMD_OTP_RESET, &entry);
    if (ret != HI_SUCCESS) {
        print_err_hex2(CMD_OTP_RESET, ret);
        return ret;
    }
    return HI_SUCCESS;
}

