/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee drv tsr2rcipher function impl.
 * Author: sdk
 * Create: 2019-08-02
 */

#include "hi_type_dev.h"
#include "hi_bitmap.h"
#include "securec.h"
#include "tee_drv_ioctl_tsr2rcipher.h"
#include "tee_drv_tsr2rcipher_func.h"
#include "tee_hal_tsr2rcipher.h"
#include "hi_tee_drv_ssm.h"
#include "hi_tee_drv_mem.h"
#include "hi_tee_drv_keyslot.h"
#include "hi_tee_drv_klad.h"

static tee_tsr2rcipher_mgmt g_tee_tsc_mgmt = {
    .io_base = TSR2RCIPHER_REGS_BASE,
    .ch_info = {
        [0 ... (TSR2RCIPHER_CH_CNT - 1)] = {
            .ch_handle = TSC_INVALID_HANDLE,
            .alg       = TSR2RCIPHER_ALG_MAX,
            .mode      = TSR2RCIPHER_MODE_MAX,
            .ks_handle = TSC_INVALID_HANDLE,
            .core_type = TSC_CORE_TYPE_MAX,
            .iv_type   = TSR2RCIPHER_IV_MAX,
        },
    },
    .ch_cnt = TSR2RCIPHER_CH_CNT,
};

static hi_void _tsr2rcipher_mutex_init(struct hi_tee_hal_mutex *lock)
{
    hi_s32 ret;
    hi_char str[16] = {0}; /* max name len of mutex is 16 */

    if (snprintf_s(str, sizeof(str), sizeof(str) - 1, "%p", lock) < 0) {
        hi_tee_drv_hal_printf("snprintf_s failed!\n");
        return;
    }

    ret = hi_tee_drv_hal_mutex_init(str, lock);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_printf("Create mutex failed, ret[0x%x]!\n", ret);
    }
}

static hi_void _tsr2rcipher_mutex_deinit(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_destroy(lock);
}

static hi_void _tsr2rcipher_mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
}

static hi_void _tsr2rcipher_mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
}

static tee_tsr2rcipher_mgmt *_tsr2rcipher_get_mgmt(hi_void)
{
    return &g_tee_tsc_mgmt;
}

static hi_bool _tsr2rcipher_ch_is_exist(hi_u32 chan_id)
{
    unsigned long mask;
    unsigned long *p = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    mask = BIT_MASK(chan_id);
    p = ((unsigned long *)tsc_mgmt->ch_bitmap) + BIT_WORD(chan_id);
    if (!(*p & mask)) {
        hi_log_err("chan_id[%d] is not created!\n", chan_id);
        return HI_FALSE;
    }

    return HI_TRUE;
}

hi_s32 tsr2rcipher_get_capability_impl(tsr2rcipher_capability *cap)
{
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    TSC_CHECK_NULL_POINTER(cap);

    cap->ts_chan_cnt = tsc_mgmt->ch_cnt;

    return HI_SUCCESS;
}

static hi_s32 _tsr2rcipher_create_impl(const tsr2rcipher_attr *tsc_attr, hi_u32 chan_id)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (tsc_attr->is_create_ks == HI_TRUE) {
        hi_handle ks_handle;
        ret = hi_drv_ks_create(HI_KEYSLOT_TYPE_TSCIPHER, &ks_handle);
        if (ret != HI_SUCCESS) {
            hi_log_err("create keyslot failed!\n");
            goto out;
        }
        rch->ks_handle = ks_handle;
    } else {
        rch->ks_handle = TSC_INVALID_HANDLE;
    }
    rch->is_create_ks = tsc_attr->is_create_ks;

    if (tsc_attr->alg == TSR2RCIPHER_ALG_AES_ECB || tsc_attr->alg == TSR2RCIPHER_ALG_AES_CBC ||
        tsc_attr->alg == TSR2RCIPHER_ALG_AES_IPTV || tsc_attr->alg == TSR2RCIPHER_ALG_AES_CTR) {
        rch->core_type = TSC_CORE_TYPE_AES;
    } else if (tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_ECB || tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_CBC ||
        tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_IPTV) {
        rch->core_type = TSC_CORE_TYPE_SMS4;
    } else {
        rch->core_type = TSC_CORE_TYPE_MAX;
    }

    rch->alg = tsc_attr->alg;
    rch->mode = tsc_attr->mode;
    rch->is_crc_check = tsc_attr->is_crc_check;
    rch->is_odd_key = tsc_attr->is_odd_key;
    rch->ch_handle = tsc_id_2_handle(chan_id);

    tee_tsc_hal_clr_chan(tsc_mgmt, chan_id);

    tee_tsc_hal_lock_config(tsc_mgmt, chan_id, HI_TRUE);

    tee_tsc_hal_rx_config(tsc_mgmt, chan_id, TSC_BUF_TYPE_LINK);
    tee_tsc_hal_tx_config(tsc_mgmt, chan_id, TSC_BUF_TYPE_LINK);

    bitmap_setbit(chan_id, tsc_mgmt->ch_bitmap);

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_create_impl(const tsr2rcipher_attr *tsc_attr, hi_handle *handle)
{
    hi_s32 ret;
    hi_u32 chan_id;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    TSC_CHECK_NULL_POINTER(tsc_attr);
    TSC_CHECK_NULL_POINTER(handle);

    _tsr2rcipher_mutex_lock(&tsc_mgmt->lock_all_ch);
    chan_id = find_first_zero_bit(tsc_mgmt->ch_bitmap, tsc_mgmt->ch_cnt);
    if (!(chan_id < tsc_mgmt->ch_cnt)) {
        hi_log_err("there is no available chan id now!\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = _tsr2rcipher_create_impl(tsc_attr, chan_id);
    if (ret != HI_SUCCESS) {
        goto out;
    }

    *handle = tsc_id_2_handle(chan_id);

out:
    _tsr2rcipher_mutex_unlock(&tsc_mgmt->lock_all_ch);

    return ret;
}

static hi_s32 _tsr2rcipher_destroy_impl(hi_u32 chan_id)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    rch->ch_handle = TSC_INVALID_HANDLE;
    rch->alg       = TSR2RCIPHER_ALG_MAX;
    rch->mode      = TSR2RCIPHER_MODE_MAX;
    rch->core_type = TSC_CORE_TYPE_MAX;
    rch->iv_type   = TSR2RCIPHER_IV_MAX;

    if (rch->is_create_ks == HI_TRUE && rch->ks_handle != TSC_INVALID_HANDLE) {
        ret = hi_drv_ks_destory(HI_KEYSLOT_TYPE_TSCIPHER, rch->ks_handle);
        if (ret != HI_SUCCESS) {
            hi_log_err("destroy keyslot failed!\n");
        }
    }

    tee_tsc_hal_lock_deconfig(tsc_mgmt, chan_id);

    tee_tsc_hal_clr_chan(tsc_mgmt, chan_id);

    bitmap_clrbit(chan_id, tsc_mgmt->ch_bitmap);

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_destroy_impl(hi_handle handle)
{
    hi_s32 ret;
    hi_u32 chan_id;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);

    _tsr2rcipher_mutex_lock(&tsc_mgmt->lock_all_ch);

    ret = _tsr2rcipher_destroy_impl(chan_id);

    _tsr2rcipher_mutex_unlock(&tsc_mgmt->lock_all_ch);

    return ret;
}

static hi_s32 _tsr2rcipher_get_attr_impl(hi_u32 chan_id, tsr2rcipher_attr *tsc_attr)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    tsc_attr->alg = rch->alg;
    tsc_attr->mode = rch->mode;
    tsc_attr->is_crc_check = rch->is_crc_check;
    tsc_attr->is_create_ks = rch->is_create_ks;
    tsc_attr->is_odd_key = rch->is_odd_key;

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_get_attr_impl(hi_handle handle, tsr2rcipher_attr *tsc_attr)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);
    TSC_CHECK_NULL_POINTER(tsc_attr);

    return _tsr2rcipher_get_attr_impl(chan_id, tsc_attr);
}

static hi_s32 _tsr2rcipher_set_attr_impl(hi_u32 chan_id, const tsr2rcipher_attr *tsc_attr)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    if (tsc_attr->alg == TSR2RCIPHER_ALG_AES_ECB || tsc_attr->alg == TSR2RCIPHER_ALG_AES_CBC ||
        tsc_attr->alg == TSR2RCIPHER_ALG_AES_IPTV || tsc_attr->alg == TSR2RCIPHER_ALG_AES_CTR) {
        rch->core_type = TSC_CORE_TYPE_AES;
    } else if (tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_ECB || tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_CBC ||
        tsc_attr->alg == TSR2RCIPHER_ALG_SMS4_IPTV) {
        rch->core_type = TSC_CORE_TYPE_SMS4;
    } else {
        rch->core_type = TSC_CORE_TYPE_MAX;
    }

    rch->alg = tsc_attr->alg;
    rch->mode = tsc_attr->mode;
    rch->is_crc_check = tsc_attr->is_crc_check;
    rch->is_odd_key = tsc_attr->is_odd_key;

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_set_attr_impl(hi_handle handle, const tsr2rcipher_attr *tsc_attr)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);
    TSC_CHECK_NULL_POINTER(tsc_attr);

    return _tsr2rcipher_set_attr_impl(chan_id, tsc_attr);
}

static hi_s32 _tsr2rcipher_get_keyslot_handle_impl(hi_u32 chan_id, hi_handle *ks_handle)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    if (rch->is_create_ks == HI_TRUE && rch->ks_handle != TSC_INVALID_HANDLE) {
        *ks_handle = rch->ks_handle;
    } else {
        hi_log_err("get keyslot handle failed!\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_get_keyslot_handle_impl(hi_handle tsc_handle, hi_handle *ks_handle)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(tsc_handle);
    tsc_check_ch_id(chan_id);
    TSC_CHECK_NULL_POINTER(ks_handle);

    return _tsr2rcipher_get_keyslot_handle_impl(chan_id, ks_handle);
}

static hi_s32 _tsr2rcipher_attach_keyslot_impl(hi_u32 chan_id, hi_handle ks_handle)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    if (rch->ks_handle != TSC_INVALID_HANDLE) {
        hi_log_err("current tsr2rcipher instance is already attached the keyslot!\n");
        ret = HI_FAILURE;
        goto out;
    }

    rch->ks_handle = ks_handle;

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_attach_keyslot_impl(hi_handle tsc_handle, hi_handle ks_handle)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(tsc_handle);
    tsc_check_ch_id(chan_id);

    return _tsr2rcipher_attach_keyslot_impl(chan_id, ks_handle);
}

static hi_s32 _tsr2rcipher_detach_keyslot_impl(hi_u32 chan_id, hi_handle ks_handle)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    if (rch->is_create_ks == HI_TRUE) {
        hi_log_err("This keyslot is created internally, it will be detached when destroying tsr2rcipher!\n");
        ret = HI_FAILURE;
        goto out;
    }

    if (rch->ks_handle != ks_handle) {
        hi_log_err("current tsr2rcipher instance is not attached this keyslot!\n");
        ret = HI_FAILURE;
        goto out;
    }

    rch->ks_handle = TSC_INVALID_HANDLE;

    ret = HI_SUCCESS;

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_detach_keyslot_impl(hi_handle tsc_handle, hi_handle ks_handle)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(tsc_handle);
    tsc_check_ch_id(chan_id);

    return _tsr2rcipher_detach_keyslot_impl(chan_id, ks_handle);
}

static hi_s32 _tsr2rcipher_set_iv_impl(hi_u32 chan_id, tsr2rcipher_iv_type iv_type, hi_u8 *iv, hi_u32 iv_len)
{
    hi_s32 ret;
    tsr2rcipher_ch *rch = HI_NULL;
    klad_clear_iv_param iv_para = {0};
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }

    if (rch->ks_handle == TSC_INVALID_HANDLE) {
        hi_log_err("ks handle is invalid!\n");
        ret = HI_FAILURE;
        goto out;
    }
    iv_para.ks_handle = rch->ks_handle;

    if (iv_type == TSR2RCIPHER_IV_EVEN) {
        iv_para.is_odd = HI_FALSE;
    } else if (iv_type == TSR2RCIPHER_IV_ODD) {
        iv_para.is_odd = HI_TRUE;
    } else {
        hi_log_err("iv type is invalid!\n");
        ret = HI_FAILURE;
        goto out;
    }

    ret = memcpy_s(iv_para.iv, HI_KLAD_MAX_IV_LEN, iv, iv_len);
    if (ret != HI_SUCCESS) {
        hi_log_err("memcpy_s failed!\n");
        _tsr2rcipher_mutex_unlock(&rch->lock_ch);
        return HI_FAILURE;
    }

    ret = hi_drv_klad_clear_iv(&iv_para);
    if (ret != HI_SUCCESS) {
        hi_log_err("set iv failed!\n");
    }

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_set_iv_impl(hi_handle handle, tsr2rcipher_iv_type iv_type, hi_u8 *iv, hi_u32 iv_len)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);
    TSC_CHECK_NULL_POINTER(iv);

    return _tsr2rcipher_set_iv_impl(chan_id, iv_type, iv, iv_len);
}

static hi_s32 __tsr2rcipher_wait_process(hi_u32 chan_id, hi_u32 time_out_ms)
{
    hi_u32 loop_time = time_out_ms / 5; /* delay 5ms every time */
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    do {
        loop_time--;
        if (tee_tsc_hal_tx_get_dsc_rd_total_int_status(tsc_mgmt, chan_id)) {
            tee_tsc_hal_tx_cls_dsc_rd_total_int_status(tsc_mgmt, chan_id);
            return HI_SUCCESS;
        }
        hi_tee_drv_hal_udelay(5000); /* delay 5000us every time */
    } while (loop_time);

    return HI_FAILURE;
}

static hi_s32 _tsr2rcipher_encrypt_impl(hi_u32 chan_id, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len)
{
    hi_s32 ret;
    bool tx_is_sec = true;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }
    if (rch->core_type == TSC_CORE_TYPE_MAX || rch->mode == TSR2RCIPHER_MODE_MAX ||
        rch->ks_handle == TSC_INVALID_HANDLE) {
        hi_log_err("current tsr2rcipher configuration is incomplete!\n");
        ret = HI_FAILURE;
        goto out;
    }
    ret = hi_tee_drv_smmu_is_sec((unsigned long)dst_addr, &tx_is_sec);
    if (ret != HI_SUCCESS) {
        hi_log_err("get smmu secure attr failed!\n");
        goto out;
    }
    tee_tsc_hal_set_sec_chan(tsc_mgmt, chan_id, HI_TRUE, tx_is_sec);

    if (!tee_tsc_hal_rx_get_dsptor_status(tsc_mgmt, chan_id)) {
        hi_log_err("rx dsc is busy!\n");
        ret = HI_FAILURE;
        goto out;
    }
    tee_tsc_hal_rx_set_buf(tsc_mgmt, chan_id, src_addr, data_len);

    if (!tee_tsc_hal_tx_get_dsptor_status(tsc_mgmt, chan_id)) {
        hi_log_err("tx dsc is busy!\n");
        ret = HI_FAILURE;
        goto out;
    }
    tee_tsc_hal_tx_set_buf(tsc_mgmt, chan_id, dst_addr, data_len);

    /* mode configure */
    tee_tsc_hal_set_mode_ctl(tsc_mgmt, rch, chan_id, TSC_CRYPT_TYPE_EN);

    hi_log_info("[Encrypt]:tsc_handle[0x%x],ks_handle[0x%x],core_type[0x%x],mode[%d],crc[%d],key_type[%d]!\n",
        rch->ch_handle, rch->ks_handle, rch->core_type, rch->mode, rch->is_crc_check, rch->is_odd_key);

    /* enable */
    tee_tsc_hal_en_mode_ctl(tsc_mgmt, chan_id);

    ret = __tsr2rcipher_wait_process(chan_id, 2000); /* time out 2000ms */
    if (ret != HI_SUCCESS) {
        hi_log_err("encrypt timeout!\n");
    }

    /* disable */
    tee_tsc_hal_dis_mode_ctl(tsc_mgmt, chan_id);

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_encrypt_impl(hi_handle handle, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);

    return _tsr2rcipher_encrypt_impl(chan_id, src_addr, dst_addr, data_len);
}

static hi_s32 _tsr2rcipher_decrypt_impl(hi_u32 chan_id, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len)
{
    hi_s32 ret;
    bool rx_is_sec = true;
    tsr2rcipher_ch *rch = HI_NULL;
    tee_tsr2rcipher_mgmt *tsc_mgmt = _tsr2rcipher_get_mgmt();

    rch = &tsc_mgmt->ch_info[chan_id];

    _tsr2rcipher_mutex_lock(&rch->lock_ch);

    if (_tsr2rcipher_ch_is_exist(chan_id) == HI_FALSE) {
        ret = HI_FAILURE;
        goto out;
    }
    if (rch->core_type == TSC_CORE_TYPE_MAX || rch->mode == TSR2RCIPHER_MODE_MAX ||
        rch->ks_handle == TSC_INVALID_HANDLE) {
        hi_log_err("current tsr2rcipher configuration is incomplete!\n");
        ret = HI_FAILURE;
        goto out;
    }
    ret = hi_tee_drv_smmu_is_sec((unsigned long)src_addr, &rx_is_sec);
    if (ret != HI_SUCCESS) {
        hi_log_err("get smmu secure attr failed!\n");
        goto out;
    }
    tee_tsc_hal_set_sec_chan(tsc_mgmt, chan_id, rx_is_sec, HI_TRUE);

    if (!tee_tsc_hal_rx_get_dsptor_status(tsc_mgmt, chan_id)) {
        hi_log_err("rx dsc is busy!\n");
        ret = HI_FAILURE;
        goto out;
    }
    tee_tsc_hal_rx_set_buf(tsc_mgmt, chan_id, src_addr, data_len);

    if (!tee_tsc_hal_tx_get_dsptor_status(tsc_mgmt, chan_id)) {
        hi_log_err("tx dsc is busy!\n");
        ret = HI_FAILURE;
        goto out;
    }
    tee_tsc_hal_tx_set_buf(tsc_mgmt, chan_id, dst_addr, data_len);

    /* mode configure */
    tee_tsc_hal_set_mode_ctl(tsc_mgmt, rch, chan_id, TSC_CRYPT_TYPE_DE);

    hi_log_info("[Decrypt]:tsc_handle[0x%x],ks_handle[0x%x],core_type[0x%x],mode[%d],crc[%d],key_type[%d]!\n",
        rch->ch_handle, rch->ks_handle, rch->core_type, rch->mode, rch->is_crc_check, rch->is_odd_key);

    /* enable */
    tee_tsc_hal_en_mode_ctl(tsc_mgmt, chan_id);

    ret = __tsr2rcipher_wait_process(chan_id, 2000); /* time out 2000ms */
    if (ret != HI_SUCCESS) {
        hi_log_err("encrypt timeout!\n");
    }

    /* disable */
    tee_tsc_hal_dis_mode_ctl(tsc_mgmt, chan_id);

out:
    _tsr2rcipher_mutex_unlock(&rch->lock_ch);

    return ret;
}

hi_s32 tsr2rcipher_decrypt_impl(hi_handle handle, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len)
{
    hi_u32 chan_id;

    chan_id = tsc_handle_2_id(handle);
    tsc_check_ch_id(chan_id);

    return _tsr2rcipher_decrypt_impl(chan_id, src_addr, dst_addr, data_len);
}

hi_s32 tsr2rcipher_mod_init_impl(hi_void)
{
    hi_u32 index;

    _tsr2rcipher_mutex_init(&g_tee_tsc_mgmt.lock_all_ch);
    for (index = 0; index < g_tee_tsc_mgmt.ch_cnt; index++) {
        _tsr2rcipher_mutex_init(&g_tee_tsc_mgmt.ch_info[index].lock_ch);
    }
    bitmap_zero(g_tee_tsc_mgmt.ch_bitmap, g_tee_tsc_mgmt.ch_cnt);

    /* configure the hardware */
    tee_tsc_hal_init_hw();

    /* enable smmu */
    tee_tsc_hal_en_mmu(&g_tee_tsc_mgmt);

    /* disable allchn */
    for (index = 0; index < g_tee_tsc_mgmt.ch_cnt; index++) {
        tee_tsc_hal_dis_mode_ctl(&g_tee_tsc_mgmt, index);
    }

    /* enable the total interrupt */
    tee_tsc_hal_top_set_int(&g_tee_tsc_mgmt, HI_TRUE, HI_TRUE, HI_FALSE);

    hi_tee_drv_ssm_iommu_config(LOGIC_MOD_ID_TSCIPHER);

    return HI_SUCCESS;
}

hi_s32 tsr2rcipher_mod_exit_impl(hi_void)
{
    hi_u32 index;

    _tsr2rcipher_mutex_deinit(&g_tee_tsc_mgmt.lock_all_ch);
    for (index = 0; index < g_tee_tsc_mgmt.ch_cnt; index++) {
        _tsr2rcipher_mutex_deinit(&g_tee_tsc_mgmt.ch_info[index].lock_ch);
    }
    bitmap_zero(g_tee_tsc_mgmt.ch_bitmap, g_tee_tsc_mgmt.ch_cnt);

    /* disable all the interrupt */
    tee_tsc_hal_top_set_int(&g_tee_tsc_mgmt, HI_FALSE, HI_FALSE, HI_FALSE);

    /* disable smmu */
    tee_tsc_hal_dis_mmu(&g_tee_tsc_mgmt);

    /* deconfigure the hardware */
    tee_tsc_hal_deinit_hw();

    return HI_SUCCESS;
}

