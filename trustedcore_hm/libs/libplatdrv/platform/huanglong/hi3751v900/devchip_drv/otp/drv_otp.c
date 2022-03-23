/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define otp driver
 * Author : Linux SDK team
 * Create: 2019/06/19
 */

#include "drv_otp.h"
#include "hal_otp.h"
#include "sys_timer.h"
#ifdef HI_OTP_TEST_SUPPORT
#include "drv_otp_proc.h"
#endif

/* structure definition */
typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_ioctl)(hi_void *arg, hi_u32 len);
} otp_ioctl_node;

static struct otp_mgmt g_otp_mgmt = {0};

struct otp_mgmt *__get_otp_mgmt(hi_void)
{
    return &g_otp_mgmt;
}

hi_void otp_timestamp(struct time_us *time)
{
    timeval_t tv;

    tv.tval64 = __SRE_ReadTimestamp();

    time->tv_sec = tv.tval.sec;
    time->tv_usec = tv.tval.nsec / TIME_US2NS;
}

static hi_void get_cost(hi_char *str, struct time_us *time_b, struct time_us *time_e)
{
    unused(str);

    if (time_b->tv_sec ==  time_e->tv_sec) {
        hi_warn_otp("%ld.%06ld s-->%ld.%06ld s, cost:%ld.%03ld ms <<%s\n",
                    time_b->tv_sec, time_b->tv_usec, time_e->tv_sec, time_e->tv_usec,
                    (time_e->tv_usec - time_b->tv_usec) / TIME_MS2US,
                    (time_e->tv_usec - time_b->tv_usec) % TIME_MS2US,
                    str);
    } else {
        hi_warn_otp("%ld.%06ld s-->%ld.%06ld s, cost:%ld.%03ld ms <<%s\n",
                    time_b->tv_sec, time_b->tv_usec, time_e->tv_sec, time_e->tv_usec,
                    ((time_e->tv_sec - time_b->tv_sec) * TIME_S2US + time_e->tv_usec - time_b->tv_usec) / TIME_MS2US,
                    ((time_e->tv_sec - time_b->tv_sec) * TIME_S2US + time_e->tv_usec - time_b->tv_usec) % TIME_MS2US,
                    str);
    }
}

hi_void otp_get_curr_cost(hi_char *str, struct time_us *time_b)
{
    struct time_us time_e;

    otp_timestamp(&time_e);
    get_cost(str, time_b, &time_e);
}

static hi_s32 _drv_otp_read(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = NULL;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry = (otp_entry *)arg;
    return hal_otp_read(entry->addr, &(entry->value));
}

static hi_s32 _drv_otp_read_byte(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = NULL;
    hi_u8 value = 0;
    hi_s32 ret;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    entry = (otp_entry *)arg;
    ret = hal_otp_read_byte(entry->addr, &value);
    entry->value = value;
    return ret;
}

static hi_s32 _drv_otp_read_bits_one_byte(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = (otp_entry *)arg;
    hi_u8 start_bit;
    hi_u8 bit_width;
    hi_u8 value;
    hi_s32 ret;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    start_bit = otp_start_bit(entry->value);
    bit_width = otp_bit_width(entry->value);
    value     = otp_value_byte(entry->value);

    if ((bit_width + start_bit > BYTE_WIDTH) || (start_bit >= BYTE_WIDTH)) {
        print_err_hex3(start_bit, start_bit, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }

    ret = hal_otp_read_bits_onebyte(entry->addr, start_bit, bit_width, &value);
    entry->value = otp_get_para(start_bit, bit_width, value);
    return ret;
}

static hi_s32 _drv_otp_write(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = (otp_entry *)arg;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    return hal_otp_write(entry->addr, entry->value);
}

static hi_s32 _drv_otp_write_byte(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = (otp_entry *)arg;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    return hal_otp_write_byte(entry->addr, (hi_u8)entry->value);
}

static hi_s32 _drv_otp_write_bit(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = (otp_entry *)arg;
    hi_u8 bit_pos;
    hi_u8 value;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    bit_pos = otp_start_bit(entry->value);
    value   = otp_value_byte(entry->value);

    if (bit_pos >= BYTE_WIDTH) {
        print_err_hex2(bit_pos, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    if (value == 0) { /* write zero, do nothing. */
        return HI_SUCCESS;
    } else if (value == 1) { /* write 1, only one bit */
        return hal_otp_write_bit(entry->addr, bit_pos);
    }
    /* only support set 1 bit */
    print_err_hex2(value, HI_ERR_OTP_INVALID_PARA);
    return HI_ERR_OTP_INVALID_PARA;
}

static hi_s32 _drv_otp_write_bits_one_byte(hi_void *arg, hi_u32 len)
{
    otp_entry *entry = (otp_entry *)arg;
    hi_u8 start_bit;
    hi_u8 bit_width;
    hi_u8 value;

    if (arg == HI_NULL) {
        return HI_ERR_OTP_PTR_NULL;
    }
    if (len != sizeof(otp_entry)) {
        print_err_hex2(len, sizeof(otp_entry));
        return HI_ERR_OTP_INVALID_PARA;
    }
    start_bit = otp_start_bit(entry->value);
    bit_width = otp_bit_width(entry->value);
    value     = otp_value_byte(entry->value);

    if ((bit_width + start_bit > BYTE_WIDTH) || (start_bit >= BYTE_WIDTH)) {
        print_err_hex3(bit_width, start_bit, HI_ERR_OTP_INVALID_PARA);
        return HI_ERR_OTP_INVALID_PARA;
    }
    return hal_otp_write_bits_onebyte(entry->addr, start_bit, bit_width, value);
}

static hi_s32 _drv_otp_reset(hi_void *arg, hi_u32 len)
{
    unused(arg);
    unused(len);
    return hal_otp_reset();
}

hi_s32 drv_otp_init(hi_void)
{
    hi_s32 ret;

    struct otp_mgmt *mgmt = __get_otp_mgmt();

    ret = mutex_init(&mgmt->lock);
    if (ret) {
        print_err_func(mutex_init, ret);
        return ret;
    }
    return HI_SUCCESS;
}

static hi_void _mutex_lock(hi_void)
{
    struct otp_mgmt *mgmt = __get_otp_mgmt();

    mutex_lock(&mgmt->lock);
}

static hi_void _mutex_unlock(hi_void)
{
    struct otp_mgmt *mgmt = __get_otp_mgmt();

    mutex_unlock(&mgmt->lock);
}

static otp_ioctl_node g_ioctl_func_map[] = {
    { CMD_OTP_READ,               _drv_otp_read },
    { CMD_OTP_READ_BYTE,          _drv_otp_read_byte },
    { CMD_OTP_READ_BITS_ONEBYTE,  _drv_otp_read_bits_one_byte },
    { CMD_OTP_WRITE,              _drv_otp_write },
    { CMD_OTP_WRITE_BYTE,         _drv_otp_write_byte },
    { CMD_OTP_WRITE_BIT,          _drv_otp_write_bit },
    { CMD_OTP_WRITE_BITS_ONEBYTE, _drv_otp_write_bits_one_byte },
    { CMD_OTP_RESET,              _drv_otp_reset },
#ifdef HI_OTP_TEST_SUPPORT
    { CMD_OTP_TEST,               otp_virtual_test },
#endif
    { CMD_OTP_MAX,                HI_NULL },
};

hi_s32 otp_ioctl_impl(unsigned int cmd, hi_void *arg, hi_u32 len)
{
    hi_s32 ret = HI_ERR_OTP_IOCTL_CMD_INVALID;
    hi_u32 size;
    otp_ioctl_node *node = HI_NULL;

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
            ret = HI_ERR_OTP_IOCTL_FUNC_NULL;
        }
        goto out;
    }

out:
    _mutex_unlock();
    return ret;
}

static hi_u32 otp_bit_count(hi_u8 n)
{
    hi_u32 count = 0;

    otp_func_enter();
    while (n > 0) {
        if ((n & 0x1) == 0x1) {
            ++count;
        }

        n >>= 0x1;
    }

    otp_func_exit();
    return count;
}

static hi_s32 get_secure_os_version(hi_u32 addr, hi_u32 length, hi_u32 *version_num)
{
    hi_u32 version_count = 0;
    hi_u32 i;
    hi_u8 value = 0;
    hi_s32 ret;

    otp_func_enter();
    for (i = 0; i < length; i++) {
        ret = hal_otp_read_byte(addr + i, &value);
        if (ret != HI_SUCCESS) {
            print_err_func_hex(hal_otp_read_byte, ret);
            goto out;
        }
        version_count += otp_bit_count(value);
    }

    *version_num = version_count;
    otp_func_exit();
out:
    return ret;
}

static hi_s32 __set_secure_os_version(hi_u32 addr, hi_u32 length)
{
    hi_u32 i;
    hi_u8 value;
    hi_s32 ret;

    otp_func_enter();
    for (i = 0; i < length; i++) {
        value = 0;
        ret = hal_otp_read_byte(addr + i, &value);
        if (ret != HI_SUCCESS) {
            print_err_func_hex(hal_otp_read_byte, ret);
            goto out;
        }

        if (value != 0xff) {
            value |= 0x1 << otp_bit_count(value);
            ret = hal_otp_write_byte(addr + i, value);
            if (ret != HI_SUCCESS) {
                print_err_func_hex(hal_otp_write_byte, ret);
                print_err_code(HI_ERR_OTP_SET_VERSION);
                ret = HI_ERR_OTP_SET_VERSION;
                goto out;
            }
            break;;
        }
    }

    otp_func_exit();
out:
    return ret;
}

static hi_s32 set_secure_os_version(hi_u32 addr, hi_u32 length, hi_u32 version)
{
    hi_u32 i;
    hi_s32 ret;
    hi_u32 version_from_otp = 0;

    otp_func_enter();
    ret = get_secure_os_version(addr, length, &version_from_otp);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(get_secure_os_version, ret);
        goto out;
    }

    if (version_from_otp > version) {
        print_err_code(HI_ERR_OTP_INVAILED_VERSION);
        ret =  HI_ERR_OTP_INVAILED_VERSION;
        goto out;
    }

    if (version > (length * BITS_PER_BYTE)) {
        print_err_code(HI_ERR_OTP_INVALID_LENGTH);
        ret = HI_ERR_OTP_INVALID_LENGTH;
        goto  out;
    }

    for (i = 0; i < (version - version_from_otp); i++) {
        ret = __set_secure_os_version(addr, length);
        if (ret != HI_SUCCESS) {
            print_err_func_hex(__set_secure_os_version, ret);
            goto out;
        }
    }

    otp_func_exit();
out:
    return ret;
}

hi_s32 hi_otp_secureos_version_get(hi_u32 *version)
{
    const hi_u32 addr = OTP_SECURE_OS_VERSION_ADDR;
    const hi_u32 length = OTP_SECURE_OS_VERSION_LEN;
    hi_s32 ret;

    otp_func_enter();
    if (version == HI_NULL) {
        print_err_code(HI_ERR_OTP_PTR_NULL);
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    ret = get_secure_os_version(addr, length, version);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(get_secure_os_version, ret);
        goto out;
    }

    otp_func_exit();
out:
    return ret;
}

hi_s32 hi_otp_secureos_version_set(hi_u32 version)
{
    hi_s32 ret;
    const hi_u32 addr = OTP_SECURE_OS_VERSION_ADDR;
    const hi_u32 length = OTP_SECURE_OS_VERSION_LEN;

    otp_func_enter();
    ret = set_secure_os_version(addr, length, version);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(set_secure_os_version, ret);
        goto out;
    }

    otp_func_exit();
out:
    return ret;
}

hi_s32 hi_drv_otp_reset(hi_void)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_reset();

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_reset);

hi_s32 hi_drv_otp_read(hi_u32 addr, hi_u32 *value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_read(addr, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_read);

hi_s32 hi_drv_otp_read_byte(hi_u32 addr, hi_u8 *value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_read_byte(addr, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_read_byte);

hi_s32 hi_drv_otp_read_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 *value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_read_bits_onebyte(addr, start_bit, bit_width, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hal_otp_read_bits_onebyte);

hi_s32 hi_drv_otp_write(hi_u32 addr, hi_u32 value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_write(addr, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_write);

hi_s32 hi_drv_otp_write_byte(hi_u32 addr, hi_u8 value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_write_byte(addr, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_write_byte);

hi_s32 hi_drv_otp_write_bit(hi_u32 addr, hi_u32 bit_pos)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_write_bit(addr, bit_pos);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_write_bit);

hi_s32 hi_drv_otp_write_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 value)
{
    hi_s32 ret;

    _mutex_lock();

    ret = hal_otp_write_bits_onebyte(addr, start_bit, bit_width, value);

    _mutex_unlock();
    return ret;
}
export_symbol(hi_drv_otp_write_bits_onebyte);

