/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file provides the otp driver interfaces.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-06
 */
#include "tee_otp_func.h"
#include "string.h"
#include "tee_otp_define.h"
#include "otp_data_struct.h"
#include "tee_otp_syscall.h"

static hi_s32 __otp_write_multi_bytes(hi_u32 addr, hi_u8 start_bit, hi_u16 bit_width,
                                      const hi_u8 *value, hi_u32 value_len)
{
    hi_s32 ret = HI_SUCCESS;
    hi_u32 i;

    if (start_bit != 0) {
        print_err_hex(start_bit);
        return HI_ERR_OTP_INVALID_PARA;
    }
    if (bits_pos_2_byte_num(start_bit, bit_width) > value_len) {
        print_err_hex3(start_bit, bit_width, value_len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    for (i = 0; i < (bit_width / 0x08); i++) {
        ret = otp_syscall_write_byte(addr + i, *(value + i));
        if (ret != HI_SUCCESS) {
            print_err_func(otp_syscall_write_byte, ret);
            return ret;
        }
    }
    if (bit_width % 0x08) {
        ret = otp_syscall_write_bits_one_byte(addr + i, 0, bit_width % 0x08, *(value + i));
        if (ret != HI_SUCCESS) {
            print_err_func(otp_syscall_write_bits_one_byte, ret);
            return ret;
        }
    }
    return ret;
}

static hi_s32 otp_write_bits(hi_u32 addr, hi_u8 start_bit, hi_u16 bit_width, const hi_u8 *value, hi_u32 value_len)
{
    /*
     * if start_bit not equal 0, start_bit plus bit_width must less than 8,
     * value_len must be 1, only write within one byte supported
     */
    if ((start_bit != 0) && (!bits_in_one_byte(start_bit, bit_width) || (value_len != 1))) {
        print_err_hex3(start_bit, bit_width, value_len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    if (bits_pos_2_byte_num(start_bit, bit_width) > value_len) {
        print_err_hex3(start_bit, bit_width, value_len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    /* one bit */
    if (bit_width == 1) {
        return otp_syscall_write_bit(addr, start_bit, *value);
    }

    /* multi bytes */
    if (start_bit == 0) {
        return __otp_write_multi_bytes(addr, start_bit, bit_width, value, value_len);
    }
    /* multi bits with in one byte */
    return otp_syscall_write_bits_one_byte(addr, start_bit, bit_width, *value);
}


static hi_s32 otp_get_crc16(const hi_u8 *data, hi_u32 len, hi_u32 *crc)
{
    hi_u8 input[KEY_LEN + 1] = {0x55};
    hi_u16 crc_value = 0xff;
    hi_bool flag;
    hi_u16 i;
    hi_u32 l;

    if (data == HI_NULL || crc == HI_NULL || len == 0 || len > KEY_LEN) {
        print_err_code(HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }

    if (memcpy_s(input + 1, sizeof(input) - 1, data, len) != EOK) {
        print_err_code(HI_ERR_OTP_SEC_FAILED);
        return HI_ERR_OTP_SEC_FAILED;
    }

    for (i = 0; i < len + 1; i++) {
        if ((input[i] * 0x100) > 0xffff) {
            hi_err_otp("Out of range ((input[i] * 0x100) > 0xffff)\n");
            return HI_ERR_OTP_OUT_OF_RANGE;
        }
        crc_value ^= (input[i] * 0x100);

        for (l = 0; l < 0x8; l++) {
            flag = ((crc_value & 0x8000) == 0x8000);
            if (((crc_value & 0x7FFF) * 0x2) > 0xffff) {
                return HI_ERR_OTP_OUT_OF_RANGE;
            }
            crc_value = (crc_value & 0x7FFF) * 0x2;
            if (flag == HI_TRUE) {
                crc_value ^= 0x8005;
            }
        }
    }
    *crc = crc_value & 0x0000ffff;
    return HI_SUCCESS;
}

static hi_s32 otp_caculate_crc(hi_u8 algorithm, const hi_u8 *value, hi_u32 value_len, hi_u32 *crc)
{
    if (algorithm == 0) {
        return otp_get_crc16(value, value_len, crc);
    } else {
        return HI_ERR_OTP_INVALID_PARA;
    }
}

static hi_s32 otp_write_crc(hi_u32 addr, hi_u8 bit_width, hi_u8 alg, const hi_u8 *value, hi_u32 value_len)
{
    hi_u32 crc = 0;
    hi_u32 j;
    hi_s32 ret;

    /*
    * crc value must be 8 bits alignment. and less than 32 bits.
    */
    if ((bit_width % 0x08) || (bits_2_byte_num(bit_width) > 0x04)) {
        print_err_hex2(bit_width, value_len);
        return HI_ERR_OTP_INVALID_PARA;
    }

    /* caculate crc */
    ret = otp_caculate_crc(alg, value, value_len, &crc);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_caculate_crc, ret);
        return ret;
    }

    /* write crc */
    for (j = 0; j < bits_2_byte_num(bit_width); j++) {
        otp_syscall_write_byte(addr + j, ((crc >> (0x08 * j)) & 0xff));
    }
    return HI_SUCCESS;
}

static hi_s32 __otp_write_multi_bytes_mask(hi_u32 addr, hi_u8 start_bit, hi_u16 bit_width)
{
    hi_s32 ret = HI_SUCCESS;
    hi_u32 i;

    if (start_bit != 0) {
        print_err_hex3(addr, start_bit, bit_width);
        return HI_ERR_OTP_INVALID_PARA;
    }

    for (i = 0; i < (bit_width / 0x08); i++) {
        ret = otp_syscall_write_byte(addr + i, 0xff);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_syscall_write_byte, ret);
            return ret;
        }
    }
    if (bit_width % 0x08) {
        ret = otp_syscall_write_bits_one_byte(addr + i, 0, bit_width % 0x08, 0xff);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_syscall_write_bits_one_byte, ret);
            return ret;
        }
    }
    return ret;
}

static hi_s32 otp_write_lock_bits(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width)
{
    /*
    * if start_bit not equal 0, start_bit plus bit_width must less than 8, only one byte supported
    */
    if ((start_bit != 0) && (!bits_in_one_byte(bit_width, start_bit))) {
        print_err_hex3(addr, start_bit, bit_width);
        return HI_ERR_OTP_INVALID_PARA;
    }

    /* one bit */
    if (bit_width == 1) {
        return otp_syscall_write_bit(addr, start_bit, 1);
    }
    /* multi bytes */
    if (start_bit == 0) {
        return __otp_write_multi_bytes_mask(addr, start_bit, bit_width);
    }
    /* within one byte */
    return otp_syscall_write_bits_one_byte(addr, start_bit, bit_width, 0xff);
}

static hi_s32 otp_check_lock_mult_bytes(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_bool *lock)
{
    hi_u32 i;
    hi_u8 data = 0;
    hi_otp_lock flag = HI_OTP_UNKNOWN;
    hi_s32 ret;

    if (start_bit != 0 || bit_width <= 0x08) {
        print_err_hex3(addr, start_bit, bit_width);
        return HI_ERR_OTP_INVALID_PARA;
    }

    for (i = 0; i < (bit_width / 0x08); i++) { /* all the bytes */
        ret = otp_syscall_read_byte(addr + i, &data);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        /*
        * first byte.
        */
        if ((data == 0xff) && (flag == HI_OTP_UNKNOWN)) {
            flag = HI_OTP_LOCKED;
        }
        if ((data == 0) && (flag == HI_OTP_UNKNOWN)) {
            flag = HI_OTP_UNLOCKED;
        }
        if (((data != 0xff) && (data != 0)) ||
            ((data == 0xff) && (flag == HI_OTP_UNLOCKED)) ||
            ((data == 0) && (flag == HI_OTP_LOCKED))) {
            hi_fatal_otp("locker value is unexpected. data=%#x\n", data);
            return HI_ERR_OTP_LOCK_UNEXPECT;
        }
    }

    if (bit_width % 0x08) { /* within the tail byte, less than 8 bits. */
        ret = otp_syscall_read_bits_one_byte(addr + i, 0, bit_width % 0x08, &data);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        /*
        * If tail bits are all set 1, and header bytes is not UNLOCKED(LOCKED or Default), return LOCKED.
        * If tail bits are all set 0, and header bytes is not LOCKED(UNLOCKED or Default), return UNLOCKED.
        * Others unexpected.
        */
        if ((data == gen_mask((bit_width % 0x08) - 1, 0)) && (flag != HI_OTP_UNLOCKED)) {
            *lock = HI_TRUE;
        } else if ((data == 0) && (flag != HI_OTP_LOCKED)) {
            *lock = HI_FALSE;
        } else {
            hi_fatal_otp("locker value is unexpected.data=%#x %#x\n", data,
                         gen_mask(bit_width + start_bit - 1, start_bit));
            return HI_ERR_OTP_LOCK_UNEXPECT;
        }
    }

    return HI_SUCCESS;
}

static hi_s32 otp_check_lock_one_byte(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_bool *lock)
{
    hi_u8 data = 0;
    hi_s32 ret;

    ret = otp_syscall_read_bits_one_byte(addr, start_bit, bit_width, &data);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_syscall_read_bits_one_byte, ret);
        return ret;
    }
    /*
    * ALL the bits set 1 indicate locked, all the bits set 0 indicate unlocked,
    * other scenarios are unexpected.
    */
    if (data == gen_mask(bit_width - 1, 0)) {
        *lock = HI_TRUE;
    } else if (data == 0) {
        *lock = HI_FALSE;
    } else {
        hi_fatal_otp("locker value is unexpected.data=%#x %#x\n", data, gen_mask(bit_width - 1, 0));
        return HI_ERR_OTP_LOCK_UNEXPECT;
    }
    return HI_SUCCESS;
}

static hi_s32 otp_check_lock_bits(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_bool *lock)
{
    hi_s32 ret;

    if (bits_in_one_byte(bit_width, start_bit)) {
        ret = otp_check_lock_one_byte(addr, start_bit, bit_width, lock);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_check_lock_one_byte, ret);
            return ret;
        }
    } else {
        ret = otp_check_lock_mult_bytes(addr, start_bit, bit_width, lock);
        if (ret != HI_SUCCESS) {
            print_err_func(otp_check_lock_mult_bytes, ret);
            return ret;
        }
    }
    return HI_SUCCESS;
}

static hi_s32 otp_check_otp_lock(const otp_data_item *otp_item, hi_bool *lock)
{
    if (with_locker(otp_item->attibute)) {
        return otp_check_lock_bits(otp_item->locker_addr, otp_item->locker_start_bit,
                                   otp_item->locker_bit_width, lock);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_check_otp_off_lock(const otp_data_item *otp_item, hi_u32 bit_off, hi_u32 bit_len, hi_bool *lock)
{
    if (with_locker(otp_item->attibute)) {
        if (bit_off + bit_len > otp_item->locker_bit_width) {
            print_err_hex3(bit_off, bit_len, otp_item->locker_bit_width);
            return HI_ERR_OTP_INVALID_PARA;
        }
        return otp_check_lock_bits(otp_item->locker_addr, otp_item->locker_start_bit + bit_off, bit_len, lock);
    }
    return HI_SUCCESS;
}

static hi_s32 otp_check_crc_lock(const otp_data_item *otp_item, hi_bool *lock)
{
    /* CHECK CRC lock */
    if (with_crc(otp_item->attibute) && with_locker(otp_item->attibute)) {
        print_dbg_hex3(otp_item->associated.crc.locker_addr,
                       otp_item->associated.crc.locker_start_bit,
                       otp_item->associated.crc.locker_bit_width);

        return otp_check_lock_bits(otp_item->associated.crc.locker_addr,
                                   otp_item->associated.crc.locker_start_bit,
                                   otp_item->associated.crc.locker_bit_width, lock);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_write_otp_lock(const otp_data_item *otp_item)
{
    /* Lock OTP */
    if (with_locker(otp_item->attibute)) {
        print_dbg_hex3(otp_item->locker_addr, otp_item->locker_start_bit, otp_item->locker_bit_width);

        return otp_write_lock_bits(otp_item->locker_addr, otp_item->locker_start_bit, otp_item->locker_bit_width);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_write_otp_off_lock(const otp_data_item *otp_item, hi_u32 bit_off, hi_u32 bit_len)
{
    /* Lock OTP */
    if (with_locker(otp_item->attibute)) {
        print_dbg_hex3(otp_item->locker_addr, otp_item->locker_start_bit, otp_item->locker_bit_width);
        print_dbg_hex2(bit_off, bit_len);

        if (bit_off + bit_len > otp_item->locker_bit_width) {
            print_err_hex3(bit_off, bit_len, otp_item->locker_bit_width);
            return HI_ERR_OTP_INVALID_PARA;
        }
        return otp_write_lock_bits(otp_item->locker_addr, otp_item->locker_start_bit + bit_off, bit_len);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_write_crc_lock(const otp_data_item *otp_item)
{
    if (with_crc(otp_item->attibute) && with_locker(otp_item->attibute)) {
        print_dbg_hex3(otp_item->associated.crc.locker_addr,
                       otp_item->associated.crc.locker_start_bit,
                       otp_item->associated.crc.locker_bit_width);

        return otp_write_lock_bits(otp_item->associated.crc.locker_addr,
                                   otp_item->associated.crc.locker_start_bit,
                                   otp_item->associated.crc.locker_bit_width);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_reset(const otp_data_item *otp_item)
{
    /* Reset OTP */
    if (need_reset(otp_item->attibute)) {
        hi_info_otp("reset otp\n");
        return otp_syscall_reset();
    }

    return HI_SUCCESS;
}

static hi_s32 otp_write_item(const otp_data_item *otp_item, const hi_u8 *value, hi_u32 value_len, hi_bool is_lock)
{
    hi_bool otp_lock = HI_FALSE;
    hi_bool crc_lock = HI_FALSE;
    hi_s32 ret;

    /* CHECK OTP/CRC lock */
    ret = otp_check_otp_lock(otp_item, &otp_lock);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = otp_check_crc_lock(otp_item, &crc_lock);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if (otp_lock == HI_TRUE) {
        hi_fatal_otp("otp locked\n");
        return HI_ERR_OTP_KEY_LOCKED;
    }

    if (crc_lock == HI_TRUE) {
        hi_fatal_otp("crc locked\n");
        return HI_ERR_OTP_CRC_LOCKED;
    }

    /* Write OTP */
    print_dbg_hex3(otp_item->addr, otp_item->start_bit, otp_item->bit_width);

    ret = otp_write_bits(otp_item->addr, otp_item->start_bit, otp_item->bit_width, value, value_len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* Write bak-region */
    /* Lock OTP */
    if (is_lock) {
        ret = otp_write_otp_lock(otp_item);
        if (ret != HI_SUCCESS) {
            return ret;
        }
    }

    /* Write and lock CRC */
    if (with_crc(otp_item->attibute)) {
        print_dbg_hex2(otp_item->associated.crc.addr, otp_item->associated.crc.bit_width);

        ret = otp_write_crc(otp_item->associated.crc.addr, otp_item->associated.crc.bit_width,
                            otp_item->associated.crc.alg, value, value_len);
        if (ret != HI_SUCCESS) {
            return ret;
        }

        if (is_lock) {
            ret = otp_write_crc_lock(otp_item);
            if (ret != HI_SUCCESS) {
                return ret;
            }
        }
    }
    /* Reset OTP */
    return otp_reset(otp_item);
}

static hi_s32 otp_read_item(const otp_data_item *otp_item, hi_u8 *value, hi_u32 *value_len)
{
    hi_u32 j;
    hi_s32 ret;

    /* read OTP */
    if (otp_item->bit_width < 0x08) {
        ret = otp_syscall_read_bits_one_byte(otp_item->addr, otp_item->start_bit, otp_item->bit_width, value);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        *value_len = 1;
    } else {
        for (j = 0; j < bits_2_byte_num(otp_item->bit_width); j++) {
            ret = otp_syscall_read_byte(otp_item->addr + j, &value[j]);
            if (ret != HI_SUCCESS) {
                return ret;
            }
        }
        *value_len = bits_2_byte_num(otp_item->bit_width);
    }

    return HI_SUCCESS;
}

static hi_s32 otp_write_item_off(const otp_data_item *otp_item, hi_u32 offset,
                                 const hi_u8 *value, hi_u32 value_len, hi_bool is_lock)
{
    hi_bool otp_lock = HI_FALSE;
    hi_s32 ret;
    hi_u32 lock_off = offset / LOCK_LONGDATA_NUM; /* 16byte data use a 1bit lock */
    hi_u32 lock_len = ((offset % LOCK_LONGDATA_NUM) + value_len + LOCK_LONGDATA_NUM - 1) / LOCK_LONGDATA_NUM;

    /* only support write bytes. */
    if (otp_item->start_bit != 0) {
        print_err_hex3(otp_item->start_bit, otp_item->bit_width, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    if (otp_item->bit_width < value_len * BITS_PER_CHAR) {
        print_err_hex3(value_len, otp_item->bit_width, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }

    /* CHECK OTP/CRC lock */
    ret = otp_check_otp_off_lock(otp_item, lock_off, lock_len, &otp_lock);
    if (ret != HI_SUCCESS) {
        print_err_func_hex3(otp_check_otp_off_lock, ret, lock_off, lock_len);
        return ret;
    }

    if (otp_lock == HI_TRUE) {
        hi_fatal_otp("otp locked\n");
        return HI_ERR_OTP_KEY_LOCKED;
    }

    /* Write OTP */
    ret = otp_write_bits(otp_item->addr + offset, 0, value_len * BITS_PER_CHAR, value, value_len);
    if (ret != HI_SUCCESS) {
        print_err_hex4(otp_item->addr, offset, value_len, ret);
        return ret;
    }

    /* Lock OTP */
    if (is_lock) {
        ret = otp_write_otp_off_lock(otp_item, lock_off, lock_len);
        if (ret != HI_SUCCESS) {
            print_err_hex4(otp_item->addr, lock_off, lock_len, ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

static hi_s32 otp_read_item_off(const otp_data_item *otp_item, hi_u32 offset, hi_u8 *value, hi_u32 *value_len)
{
    hi_u32 j;
    hi_s32 ret;

    if (offset + (*value_len) > bits_2_byte_num(otp_item->bit_width)) {
        print_err_hex2(offset, otp_item->bit_width);
        *value_len = 0;
        return HI_ERR_OTP_INVALID_PARA;
    }
    for (j = 0; j < (*value_len); j++) {
        ret = otp_syscall_read_byte(otp_item->addr + j + offset, &value[j]);
        if (ret != HI_SUCCESS) {
            return ret;
        }
    }
    return HI_SUCCESS;
}

static hi_s32 otp_write_item_lock(const otp_data_item *otp_item)
{
    hi_bool otp_lock = HI_FALSE;
    hi_s32 ret;

    /* CHECK OTP lock */
    ret = otp_check_otp_lock(otp_item, &otp_lock);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_check_otp_lock, ret);
        return ret;
    }

    if (otp_lock == HI_TRUE) {
        return HI_SUCCESS;
    }

    /* Write OTP Lock */
    return otp_write_otp_lock(otp_item);
}

static hi_s32 otp_read_item_lock(const otp_data_item *otp_item, hi_bool *is_lock)
{
    hi_s32 ret;
    hi_u8 data = 0;

    /* Read OTP lock */
    if (with_locker(otp_item->attibute)) {
        ret = otp_syscall_read_byte(otp_item->locker_addr, &data);
        if (ret) {
            print_err_func(otp_syscall_read_byte, ret);
            return ret;
        }

        *is_lock = (hi_bool)((data >> otp_item->locker_start_bit) & 0x1);
        return HI_SUCCESS;
    }
    return HI_ERR_OTP_NOT_SUPPORT;
}

static hi_s32 otp_get_item_value(const hi_char *fuse_name, otp_data_item **item_pv)
{
    hi_u32 i;
    otp_data_item *otp_data = HI_NULL;

    otp_data = otp_get_data();
    for (i = 0; i < otp_get_data_number(); i++) {
        if (0 == strncmp(fuse_name, (const char *)otp_data[i].field_name, OTP_FIELD_NAME_MAX_LEN)) {
            *item_pv = otp_data + i;
            return HI_SUCCESS;
        }
    }
    hi_err_otp("pv name not found.\n");
    return HI_ERR_OTP_NOT_FOUND;
}

hi_s32 otp_func_burn_item(const hi_char *fuse_name, const hi_u8 *value, hi_u32 value_len, hi_bool is_lock)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if ((fuse_name == HI_NULL) || (value == HI_NULL)) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }
    ret = otp_write_item(otp_item, value, value_len, is_lock);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_write_item, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_func_read_item(const hi_char *fuse_name, hi_u8 *value, hi_u32 *value_len)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if ((fuse_name == HI_NULL) || (value == HI_NULL) || (value_len == HI_NULL)) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }
    ret = otp_read_item(otp_item, value, value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_read_item, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_func_burn_item_off(const hi_char *fuse_name, hi_u32 offset,
                              const hi_u8 *value, hi_u32 value_len, hi_bool is_lock)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if ((fuse_name == HI_NULL) || (value == HI_NULL)) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }

    ret = otp_write_item_off(otp_item, offset, value, value_len, is_lock);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_write_item_off, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_func_read_item_off(const hi_char *fuse_name, hi_u32 offset, hi_u8 *value, hi_u32 *value_len)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if ((fuse_name == HI_NULL) || (value == HI_NULL) || (value_len == HI_NULL)) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }

    ret = otp_read_item_off(otp_item, offset, value, value_len);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_read_item_off, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_func_read_item_lock(const hi_char *fuse_name, hi_bool *is_lock)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if (fuse_name == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }
    ret = otp_read_item_lock(otp_item, is_lock);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_read_item_lock, ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_s32 otp_func_write_item_lock(const hi_char *fuse_name)
{
    hi_s32 ret;
    otp_data_item *otp_item = HI_NULL;

    if (fuse_name == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        return HI_ERR_OTP_PTR_NULL;
    }

    ret = otp_get_item_value(fuse_name, &otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_get_item_value, ret);
        return ret;
    }
    ret = otp_write_item_lock(otp_item);
    if (ret != HI_SUCCESS) {
        print_err_func(otp_write_item_lock, ret);
        return ret;
    }
    return HI_SUCCESS;
}
