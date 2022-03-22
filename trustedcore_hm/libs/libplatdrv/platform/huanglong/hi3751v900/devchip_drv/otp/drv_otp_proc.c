/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description :Add proc node in virtual fs.
 * Author : Linux SDK team
 * Created : 2019-10-12
 */
#include "drv_otp_proc.h"
#include "drv_otp_define.h"
#include "hal_otp.h"

/* ****** proc virtualotp begin ******* */
#define OTP_FUSE_MAX     0X1000

#define OTP_VIRTUAL_VALUE_LEN 0x10

typedef enum {
    DRV_OTP_NO_FAKE_FLAG               = 0X00,
    DRV_OTP_GET_FAKE_BUFFER_FLAG       = 0X01,
    DRV_OTP_FAKE_BUFFER_FLAG           = 0X10,
    DRV_OTP_FAKE_BUFFER_RESET_FLAG     = 0X11,
    DRV_OTP_FAKE_ACCESS_ERR_FLAG       = 0X20,
    DRV_OTP_FAKE_CLEAR_BUFFER          = 0X30,
    DRV_OTP_FAKE_MAX
} drv_otp_fake_flag;

static hi_u8  g_fake_otp_buffer[OTP_FUSE_MAX] = {0};
static drv_otp_fake_flag g_fake_otp_flag = DRV_OTP_NO_FAKE_FLAG;

static hi_bool _fake_otp_buffer_flag(hi_void)
{
    if (g_fake_otp_flag == DRV_OTP_FAKE_BUFFER_FLAG) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

static hi_bool _fake_otp_access_err_flag(hi_void)
{
    if (g_fake_otp_flag == DRV_OTP_FAKE_ACCESS_ERR_FLAG) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

static hi_s32 _fake_otp_get_flag(hi_void)
{
    return g_fake_otp_flag;
}

static hi_s32 _fake_otp_clear_buffer(hi_void)
{
    hi_s32 ret;
    hi_info_otp("clean OTP fake buffer\n");

    ret = (memset_s(g_fake_otp_buffer, sizeof(g_fake_otp_buffer), 0, sizeof(g_fake_otp_buffer)));
    if (ret != EOK) {
        return HI_ERR_OTP_SEC_FAILED;
    }

    return HI_SUCCESS;
}

static hi_s32 _fake_otp_reset_virtual_otp(hi_void)
{
    hi_s32 ret;
    hi_u32 index;

    ret = memset_s(g_fake_otp_buffer, sizeof(g_fake_otp_buffer), 0, sizeof(g_fake_otp_buffer));
    if (ret != EOK) {
        return HI_ERR_OTP_SEC_FAILED;
    }

    for (index = 0; index < OTP_FUSE_MAX; index++) {
        ret = hal_otp_read_byte(index, &g_fake_otp_buffer[index]);
        if (ret != EOK) {
            hi_err_otp("Failed to hal_otp_read_byte func, ret = 0x%x\n", ret);
            return HI_ERR_OTP_SEC_FAILED;
        }
    }

    return HI_SUCCESS;
}

static hi_s32 _fake_otp_read_byte(hi_u32 addr)
{
    if (addr >= OTP_FUSE_MAX) {
        return HI_SUCCESS;
    }

    return g_fake_otp_buffer[addr];
}

static hi_s32 _fake_otp_write_byte(hi_u32 addr, hi_u8 value)
{
    if (addr >= OTP_FUSE_MAX) {
        return HI_ERR_OTP_INVALID_ADDR;
    }

    g_fake_otp_buffer[addr] = g_fake_otp_buffer[addr] | value;

    return HI_SUCCESS;
}

/*
 * below command is just use for OTP test.
 * value[0]:type
 * value[1]~value[15]:parameter
 */
static hi_u32 _otp_virtual_test(hi_u8 *value, hi_u32 len)
{
    hi_s32 ret = HI_SUCCESS;

    if (len != OTP_VIRTUAL_VALUE_LEN) {
        hi_err_otp("Illegal parameter.\n");
    }

    switch (value[0]) {
        case DRV_OTP_GET_FAKE_BUFFER_FLAG:  /* 0x01 */
            ret = _fake_otp_get_flag();
            value[0x1] = (hi_u8)0xAA;
            value[0x2] = (hi_u8)ret;
            hi_err_otp("Get OTP special test flag(0X%02x)\n", ret);
            ret = HI_SUCCESS;
            break;
        case DRV_OTP_FAKE_BUFFER_FLAG:       /* 0x10 */
        case DRV_OTP_FAKE_BUFFER_RESET_FLAG: /* 0x11 */
            g_fake_otp_flag = 0x0;
            ret = _fake_otp_reset_virtual_otp();
            if (ret != HI_SUCCESS) {
                hi_err_otp("Reset virutal OTP failed.\n");
            }
            g_fake_otp_flag = value[0];
            hi_err_otp("Set OTP special test flag(0X%02x)(Reset or Init).\n", value[0]);
            break;
        case DRV_OTP_FAKE_ACCESS_ERR_FLAG:  /* 0x20 */
        case DRV_OTP_NO_FAKE_FLAG:          /* 0x00 */
            g_fake_otp_flag = value[0];
            hi_err_otp("Set OTP special test flag(0X%02x).\n", value[0]);
            break;
        case DRV_OTP_FAKE_CLEAR_BUFFER:     /* 0x30 */
            ret = _fake_otp_clear_buffer();
            if (ret != HI_SUCCESS) {
                hi_err_otp("Cleaning virutal OTP failed.\n");
            }
            hi_err_otp("Set OTP special test flag(0X%02x)(Clean).\n", value[0]);
            break;
        default:
            ret = HI_ERR_OTP_NO_SUCH_OPTION;
            break;
    }

    return ret;
}

hi_s32 fake_otp_virtual_read(hi_u32 addr, hi_u32 *value)
{
    hi_s32 ret = HI_SUCCESS;

    if (value == HI_NULL) {
        ret = HI_ERR_OTP_PTR_NULL;
        goto out;
    }

    if (_fake_otp_access_err_flag() == HI_TRUE) {
        ret = HI_ERR_OTP_FAKE_ACCESS_FAILED;
        goto out;
    }

    if (_fake_otp_buffer_flag() != HI_TRUE) {
        ret = HI_ERR_OTP_NON_FAKE_MODE;
        goto out;
    }

    *value = _fake_otp_read_byte(addr + 0x00) +
             _fake_otp_read_byte(addr + 0x01) * 0x100 +
             _fake_otp_read_byte(addr + 0x02) * 0x10000 +
             _fake_otp_read_byte(addr + 0x03) * 0x1000000; /* get one word */

out:
    return ret;
}

hi_s32 fake_otp_virtual_write_byte(hi_u32 addr, hi_u8 value)
{
    if (_fake_otp_access_err_flag() == HI_TRUE) {
        return HI_ERR_OTP_FAKE_ACCESS_FAILED;
    }

    if (_fake_otp_buffer_flag() != HI_TRUE) {
        return HI_ERR_OTP_NON_FAKE_MODE;
    } else {
        return _fake_otp_write_byte(addr, (hi_u8)(value & 0xff));
    }
}

hi_s32 otp_virtual_test(hi_void *arg, hi_u32 len)
{
    hi_s32 ret;
    hi_u8 value[OTP_VIRTUAL_VALUE_LEN] = {0};

    ret = memcpy_s(value, sizeof(value), arg, len);
    if (ret != EOK) {
        return HI_ERR_OTP_SEC_FAILED;
    }

    return _otp_virtual_test(value, sizeof(value));
}

/* ****** proc virtualotp end ******* */
hi_s32 otp_end(hi_void)
{
    return HI_SUCCESS;
}
