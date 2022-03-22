/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert hal layer general implementation
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-24
 */
#include "tee_hal_cert.h"
#include "tee_drv_cert.h"
#include "tee_hal_cert_reg.h"

/* Register read and write */
#define reg_read(addr, result)  ((result) = *(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, result)  (*(volatile unsigned int *)(uintptr_t)(addr) = (result))

static hi_void _cert_write_reg(const hi_u32 addr, const hi_u32 val)
{
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    if ((addr >= AKL_REG_BASE) &&
        (addr < (AKL_REG_RANGE + AKL_REG_BASE))) {
        reg_write((mgmt->io_base + (addr - AKL_REG_BASE)), val);
    } else if ((addr >= OTP_SHADOW_REG_BASE) && (addr < (OTP_SHADOW_REG_RANGE + OTP_SHADOW_REG_BASE))) {
        reg_write((mgmt->io_otp_shadow + (addr - OTP_SHADOW_REG_BASE)), val);
    } else {
        hi_info_cert("ERROR address 0x%08x.\n", addr);
    }
    hi_info_cert("cert w 0x%08x 0x%08x\n", addr, val);
}

static hi_u32 _cert_read_reg(const hi_u32 addr)
{
    hi_u32 val;
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    val = 0;
    if ((addr >= AKL_REG_BASE) &&
        (addr < (AKL_REG_RANGE + AKL_REG_BASE))) {
        reg_read(mgmt->io_base + (addr - AKL_REG_BASE), val);
    } else if ((addr >= OTP_SHADOW_REG_BASE) && (addr < (OTP_SHADOW_REG_RANGE + OTP_SHADOW_REG_BASE))) {
        reg_read(mgmt->io_otp_shadow + (addr - OTP_SHADOW_REG_BASE), val);
    } else {
        hi_info_cert("ERROR address 0x%08x.\n", addr);
    }

    hi_info_cert("cert r 0x%08x 0x%08x\n", addr, val);
    return val;
}

hi_u32 hal_cert_read_reg(const hi_u32 addr)
{
    return _cert_read_reg(addr);
}

hi_void hal_cert_write_reg(const hi_u32 addr, const hi_u32 val)
{
    _cert_write_reg(addr, val);
}

hi_u32 hal_cert_get_status(hi_void)
{
    return _cert_read_reg(AKL_STATUS);
}

hi_bool hal_cert_key_pending(hi_void)
{
    akl_status stat;

    stat.u32 = _cert_read_reg(AKL_STATUS);

    return (hi_bool)stat.bits.key_output;
}

hi_bool hal_cert_ip_err(hi_void)
{
    akl_status stat;

    stat.u32 = _cert_read_reg(AKL_STATUS);

    return (hi_bool)stat.bits.cert_ip_err;
}

hi_void hal_cert_set_command(hi_u32 cmd)
{
    _cert_write_reg(AKL_CAMMAND, cmd | 0x1);
    hi_dbg_cert("write: command[0x%x]\n", cmd);
    return ;
}

hi_u32 hal_cert_get_command(hi_void)
{
    return _cert_read_reg(AKL_CAMMAND);
}

hi_u32 hal_cert_get_metadata(hi_void)
{
    return _cert_read_reg(AKL_KEY_META_DATA);
}

hi_s32 hal_cert_wait_done(hi_cert_timeout time_out)
{
    hi_u32 cnt = 0;
    hi_u32 max;

    cert_func_enter();
    if (time_out == HI_CERT_TIMEOUT_OTP) {
        max = US_CERT_TIMEOUT_OTP;
    } else {
        max = US_CERT_TIMEOUT_DEFAULT;
    }

    max = max / 10; /* Reduce the maximum limit by 10 times */
    while ((hal_cert_get_command() & 0x1) != 0) {
        udelay(10); /* the delay is 10 microseconds */
        cnt++;
        if (cnt >= max) {
            hi_err_cert("wait too long, sta=0x%08x.\n", hal_cert_get_status());
            return HI_ERR_CERT_TIMEOUT;
        }
    }
    cert_func_exit();
    return HI_SUCCESS;
}

hi_void hal_cert_lock(hi_void)
{
    akl_lock lock;

    lock.bits.akl_lock = 1;
    _cert_write_reg(AKL_LOCK, lock.u32);
}

hi_void hal_cert_unlock(hi_void)
{
    akl_lock lock;

    lock.bits.akl_lock = 0;
    _cert_write_reg(AKL_LOCK, lock.u32);
}

hi_bool hal_cert_is_locked(hi_void)
{
    akl_lock_state stat;

    stat.u32 = _cert_read_reg(AKL_LOCK_STATE);
    if (stat.bits.akl_lock_status == AKL_LOCK_TEE) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

hi_bool hal_cert_is_unlocked(hi_void)
{
    akl_lock_state stat;

    stat.u32 = _cert_read_reg(AKL_LOCK_STATE);
    if (stat.bits.akl_lock_status == AKL_LOCK_IDLE) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

hi_u32 hal_cert_key_send(hi_void)
{
    hi_s32 ret = HI_ERR_CERT_TIMEOUT;
    akl_key_send_done send_reg;
    hi_u32 time;

    send_reg.bits.all_done = 1;
    _cert_write_reg(AKL_KEY_SEND_NODE, send_reg.u32);

    for (time = 0; time < 1000000; time++) { /* The time limit is 1000000 */
        send_reg.u32 = _cert_read_reg(AKL_KEY_SEND_NODE);
        if (send_reg.bits.all_done == 0) {
            ret = HI_SUCCESS;
            goto out;
        }
        udelay(10); /* the delay is 10 microseconds */
    }

    hi_err_cert("key send time out..dbg=0x%x\n", _cert_read_reg(AKL_DBG_STATE));

out:
    return ret;
}

hi_s32 hal_cert_key_send_ctl(akl_key_send_ctl reg)
{
    hi_s32 ret = HI_ERR_CERT_TIMEOUT;
    akl_key_send_ctl ctl;
    akl_status stat;
    hi_u32 time;

    stat.u32 = _cert_read_reg(AKL_STATUS);
    if (stat.bits.key_output == 0) {
        hi_err_cert("key is invalid\n");
        ret = HI_ERR_CERT_KEY_INVALID;
        goto out;
    }

    _cert_write_reg(AKL_KEY_SEND_CTRL, reg.u32);
    for (time = 0; time < 1000000; time++) { /* The time limit is 1000000 */
        ctl.u32 = _cert_read_reg(AKL_KEY_SEND_CTRL);

        if (ctl.bits.send_start == 0) {
            ret = HI_SUCCESS;
            goto out;
        }
        udelay(10); /* the delay is 10 microseconds */
    }

out:
    return ret;
}

hi_u32 hal_cert_get_key_send_ctl(hi_void)
{
    return _cert_read_reg(AKL_KEY_SEND_CTRL);
}

hi_s32 hal_cert_check_key_status(hi_void)
{
    hi_s32 ret = HI_SUCCESS;
    akl_status stat;
    akl_gen_error err;
    akl_kc_send_error kc_err;

    stat.u32 = _cert_read_reg(AKL_STATUS);
    if (stat.bits.key_output == 0) {
        hi_err_cert("key is not valid\n");
        ret = HI_ERR_CERT_KEY_INVALID;
        goto out;
    }

    err.u32 = _cert_read_reg(AKL_GEN_ERROR);
    kc_err.u32 = _cert_read_reg(AKL_KC_SEND_ERROR);

    if (err.u32 != 0 || kc_err.u32 != 0) {
        hi_err_cert("akl err 0x%08x, kc_send_err 0x%08x, metadata 0x%08x\n",
            err.u32, kc_err.u32, _cert_read_reg(AKL_KEY_META_DATA));
        ret = HI_ERR_CERT_DBG_OTHER_ERR;
        goto out;
    }

out:
    return ret;
}

hi_u32 hal_cert_gen_err(hi_void)
{
    return _cert_read_reg(AKL_GEN_ERROR);
}

hi_u32 hal_cert_gen_kc_err(hi_void)
{
    return _cert_read_reg(AKL_KC_SEND_ERROR);
}

hi_u32 hal_cert_meta_data(hi_void)
{
    return _cert_read_reg(AKL_KEY_META_DATA);
}

hi_void hal_cert_get_data_in(akl_data *data_in)
{
    if (data_in == HI_NULL) {
        return;
    }

    data_in->data[0x0] = _cert_read_reg(DATA_IN_0);
    data_in->data[0x1] = _cert_read_reg(DATA_IN_1);
    data_in->data[0x2] = _cert_read_reg(DATA_IN_2);
    data_in->data[0x3] = _cert_read_reg(DATA_IN_3);
    data_in->data[0x4] = _cert_read_reg(DATA_IN_4);
    data_in->data[0x5] = _cert_read_reg(DATA_IN_5);
    data_in->data[0x6] = _cert_read_reg(DATA_IN_6);
    data_in->data[0x7] = _cert_read_reg(DATA_IN_7);
    return ;
}

hi_void hal_cert_set_data_in(const akl_data *data_in)
{
    if (data_in == HI_NULL) {
        return;
    }
    _cert_write_reg(DATA_IN_0, data_in->data[0x0]);
    _cert_write_reg(DATA_IN_1, data_in->data[0x1]);
    _cert_write_reg(DATA_IN_2, data_in->data[0x2]);
    _cert_write_reg(DATA_IN_3, data_in->data[0x3]);
    _cert_write_reg(DATA_IN_4, data_in->data[0x4]);
    _cert_write_reg(DATA_IN_5, data_in->data[0x5]);
    _cert_write_reg(DATA_IN_6, data_in->data[0x6]);
    _cert_write_reg(DATA_IN_7, data_in->data[0x7]);
    return ;
}

hi_void hal_cert_get_data_out(akl_data *data_out)
{
    if (data_out == HI_NULL) {
        return;
    }

    data_out->data[0x0] = _cert_read_reg(DATA_OUT_0);
    data_out->data[0x1] = _cert_read_reg(DATA_OUT_1);
    data_out->data[0x2] = _cert_read_reg(DATA_OUT_2);
    data_out->data[0x3] = _cert_read_reg(DATA_OUT_3);
    data_out->data[0x4] = _cert_read_reg(DATA_OUT_4);
    data_out->data[0x5] = _cert_read_reg(DATA_OUT_5);
    data_out->data[0x6] = _cert_read_reg(DATA_OUT_6);
    data_out->data[0x7] = _cert_read_reg(DATA_OUT_7);
}

hi_void hal_cert_reset(hi_void)
{
    akl_rst_req reg;

    reg.bits.akl_rst_req = 1;
    _cert_write_reg(AKL_RST_REQ, reg.u32);
    msleep(100); /* sleep 100 milliseconds */

    reg.bits.akl_rst_req = 0;
    _cert_write_reg(AKL_RST_REQ, reg.u32);

    msleep(100); /* sleep 100 milliseconds */
}

hi_void hal_cert_set_sec_en(hi_void)
{
    akl_sec_en sec;

    sec.u32 = 0;
    sec.bits.akl_sec_en = 1;
    _cert_write_reg(AKL_SEC_EN, sec.u32);
}

hi_void hal_cert_set_sec_dis(hi_void)
{
    akl_sec_en sec;

    sec.u32 = 0;
    sec.bits.akl_sec_en = 0;
    _cert_write_reg(AKL_SEC_EN, sec.u32);
}

hi_bool hal_cert_get_sec_stat(hi_void)
{
    akl_sec_en sec;

    sec.u32 = _cert_read_reg(AKL_SEC_EN);;

    return (hi_bool)sec.bits.akl_sec_en;
}

hi_bool hal_cert_pv_activated(hi_void)
{
    hi_u32 reg;

    reg = _cert_read_reg(AKL_PV_SHADOW_REG);
    reg = reg >> 24; /* right shift 24 bit */
    /* 0x0a  non-privileged mode, others privileged mode */
    if (((reg >> 4) & 0xf) == 0x0a) { /* bit 4 ~ bit 7 indicate privileged mode. */
        return HI_FALSE;
    }
    return HI_TRUE;
}

hi_s32 hal_cert_init(hi_void)
{
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    mgmt->io_base = AKL_REG_BASE;

    mgmt->io_otp_shadow = OTP_SHADOW_REG_BASE;

    return HI_SUCCESS;
}

hi_void hal_cert_deinit(hi_void)
{
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    mgmt->io_base = 0;
    mgmt->io_otp_shadow = 0;

    return;
}
