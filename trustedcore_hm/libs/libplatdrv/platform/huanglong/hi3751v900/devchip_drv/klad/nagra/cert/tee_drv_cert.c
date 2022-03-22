/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Key slot driver.Provide all the kernel API and ioctl API.
 * Author: Linux SDK team
 * Create: 2019-08-23
 */

#include "tee_drv_cert.h"

#include <sched.h>

#include "tee_drv_cert_ioctl.h"
#include "tee_hal_cert.h"


/* structure definition */
struct engine_2_dsc_mode {
    hi_crypto_engine_alg engine;
    hi_u8 reg_dsc_mode;
};

typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_ioctl)(hi_void *arg);
} cert_ioctl_node;

static struct cert_mgmt g_cert_mgmt = {
    .lock      = __mutex_initializer(g_cert_mgmt.lock),
    .owner     = 0,
    .key_used  = HI_FALSE,
};

struct cert_mgmt *__get_cert_mgmt(hi_void)
{
    return &g_cert_mgmt;
}

/* static internal API definition */
static hi_s32 _valid_mmap_phys_addr_range(hi_size_t pfn, size_t size, hi_size_t mask)
{
    return (pfn + (size >> PAGE_SHIFT)) <= (1 + (mask >> PAGE_SHIFT));
}

hi_void _cert_mutex_lock(hi_void)
{
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    __mutex_lock(&mgmt->lock);
}

hi_void _cert_mutex_unlock(hi_void)
{
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    __mutex_unlock(&mgmt->lock);
}

static hi_void __drv_cert_sec_init(hi_void)
{
    hal_cert_set_sec_dis();

    return;
}

static hi_s32 __drv_cert_init(hi_void)
{
    hi_s32 ret;

    ret = hal_cert_init();
    if (ret != HI_SUCCESS) {
        print_err_func(hal_cert_init, ret);
        return ret;
    }

    hal_cert_reset();

    __drv_cert_sec_init();

    return ret;
}

hi_s32 drv_cert_init(hi_void)
{
    return __drv_cert_init();
}

static hi_void __drv_cert_deinit(hi_void)
{
    hal_cert_reset();

    __drv_cert_sec_init();

    hal_cert_deinit();

    return;
}

hi_void drv_cert_deinit(hi_void)
{
    __drv_cert_deinit();

    return;
}

static hi_void __drv_cert_store_data_out(akl_data *data, hi_cert_command *cmd)
{
    hi_u8 i;

    for (i = 0; i < DATA_NUM; i++) {
        *((hi_u32 *)(cmd->output_data) + i) =  data->data[i];
    }
    return;
}

static hi_void __drv_cert_store_status(hi_u32 status, hi_cert_command *cmd)
{
    *(hi_u32 *)(&cmd->status) = status;
    return;
}

static hi_void __drv_cert_get_data_in(hi_cert_command *cmd, akl_data *data_in)
{
    hi_u8 i;

    for (i = 0; i < DATA_NUM; i++) {
        data_in->data[i] =  *(hi_u32 *)(&cmd->input_data[i * DATA_LEN]);
    }
}

static hi_u32 __drv_cert_get_op_code(hi_cert_command *cmd)
{
    return *(hi_u32 *)(&cmd->opcodes);
}

static hi_s32 __drv_cert_exchange(hi_cert_res_handle *handle, hi_cert_command *cmd)
{
    akl_data data_in = {{0}};
    akl_data data_out = {{0}};
    hi_u32 opcodes;
    TEE_UUID cur_uid = {0};
    hi_s32 ret;

    struct cert_mgmt *mgmt = __get_cert_mgmt();

    ret = hi_tee_drv_hal_current_uuid(&cur_uid);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_tee_drv_hal_current_uuid, ret);
        return ret;
    }

    ret = memcmp((TEE_UUID *)handle->res_handle, &cur_uid, sizeof(TEE_UUID));
    if (ret != EOK) {
        hi_err_cert("Invalid Key Handle 0x%x\n", handle->res_handle);
        return HI_ERR_CERT_INVALID_HANDLE;
    }

    if (hal_cert_key_pending() && mgmt->key_used == HI_TRUE) { /* not use, key pending on the bus. */
        /* acknowledge cert */
        hal_cert_key_send();
        mgmt->key_used = HI_FALSE;
    }

    __drv_cert_get_data_in(cmd, &data_in);
    opcodes = __drv_cert_get_op_code(cmd);

    /* set data in, command */
    hal_cert_set_data_in(&data_in);

    hal_cert_set_command(opcodes);

    if (hal_cert_wait_done(cmd->timeout) != HI_SUCCESS) {
        return HI_ERR_CERT_TIMEOUT;
    }

    /* get data out, status. */
    hal_cert_get_data_out(&data_out);

    __drv_cert_store_data_out(&data_out, cmd);

    __drv_cert_store_status(hal_cert_get_status(), cmd);

    if (hal_cert_ip_err()) {
        /* in order to copy buf to usr,so return value must > 0,but not success */
        return HI_ERR_CERT_UNEXPECTED_STA & 0x7fffffff;
    }
    return HI_SUCCESS;
}

static hi_s32 _drv_cert_exchange(hi_void *arg)
{
    hi_s32 ret;
    cert_cmd_ctl *ctl = (cert_cmd_ctl *)arg;

    if (arg == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    ret = __drv_cert_exchange(&ctl->handle, &ctl->cmd);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_exchange, ret);
    }

out:
    return ret;
}

static hi_u8 __port_sel_gen(hi_cert_key_port_sel port_sel)
{
    /* 2 bits, 0b00 tscipher, 0b01 mcipher, others reserved. */
    if (port_sel == HI_CERT_KEY_PORT_MCIPHER) {
        return 0x01;
    } else if (port_sel == HI_CERT_KEY_PORT_TSCIPHER) {
        return 0x00;
    } else {
        return 0x03;
    }
}

static struct engine_2_dsc_mode g_dsc_mode_reg_map[] = {
    { HI_CRYPTO_ENGINE_ALG_CSA2,             0x00 },
    { HI_CRYPTO_ENGINE_ALG_CSA3,             0x10 },
    { HI_CRYPTO_ENGINE_ALG_ASA,              0x91 },
    { HI_CRYPTO_ENGINE_ALG_ASA_LIGHT,        0x92 },

    { HI_CRYPTO_ENGINE_ALG_AES_ECB_T,        0x21 },
    { HI_CRYPTO_ENGINE_ALG_AES_ECB_L,        0x24 },

    { HI_CRYPTO_ENGINE_ALG_AES_CBC_T,        0x22 },
    { HI_CRYPTO_ENGINE_ALG_AES_CISSA,        0x22 },
    { HI_CRYPTO_ENGINE_ALG_AES_CBC_L,        0x25 },

    { HI_CRYPTO_ENGINE_ALG_AES_CBC_IDSA,     0x20 },
    { HI_CRYPTO_ENGINE_ALG_AES_IPTV,         0x20 },
    { HI_CRYPTO_ENGINE_ALG_AES_CTR,          0x26 },

    { HI_CRYPTO_ENGINE_ALG_DES_CI,           0x33 },
    { HI_CRYPTO_ENGINE_ALG_DES_CBC,          0x33 },
    { HI_CRYPTO_ENGINE_ALG_DES_CBC_IDSA,     0x30 },

    { HI_CRYPTO_ENGINE_ALG_SMS4_ECB,         0x51 },
    { HI_CRYPTO_ENGINE_ALG_SMS4_CBC,         0x53 },
    { HI_CRYPTO_ENGINE_ALG_SMS4_CBC_IDSA,    0x50 },

    { HI_CRYPTO_ENGINE_ALG_TDES_ECB,         0x71 },
    { HI_CRYPTO_ENGINE_ALG_TDES_CBC,         0x73 },
    { HI_CRYPTO_ENGINE_ALG_TDES_CBC_IDSA,    0x70 },

    { HI_CRYPTO_ENGINE_ALG_MULTI2_ECB,       0x81 },
    { HI_CRYPTO_ENGINE_ALG_MULTI2_CBC,       0x83 },
    { HI_CRYPTO_ENGINE_ALG_MULTI2_CBC_IDSA,  0x80 },

    { HI_CRYPTO_ENGINE_ALG_RAW_AES,          0x20 },
    { HI_CRYPTO_ENGINE_ALG_RAW_DES,          0x30 },
    { HI_CRYPTO_ENGINE_ALG_RAW_SM4,          0x50 },
    { HI_CRYPTO_ENGINE_ALG_RAW_TDES,         0x70 },
    { HI_CRYPTO_ENGINE_ALG_RAW_HMAC_SHA1,    0xa0 },
    { HI_CRYPTO_ENGINE_ALG_RAW_HMAC_SHA2,    0xa1 },
    { HI_CRYPTO_ENGINE_ALG_RAW_HMAC_SM3,     0xa2 },
    { HI_CRYPTO_ENGINE_ALG_RAW_HDCP,         0xf0 },
    { HI_CRYPTO_ENGINE_ALG_MAX,              0xff }
};

static hi_s32 __dsc_mode_gen(hi_crypto_engine_alg engine, hi_u8 *sw_type)
{
    hi_u8 i;

    for (i = 0; i < sizeof(g_dsc_mode_reg_map) / sizeof(struct engine_2_dsc_mode); i++) {
        if (engine == g_dsc_mode_reg_map[i].engine) {
            *sw_type = g_dsc_mode_reg_map[i].reg_dsc_mode;
            return HI_SUCCESS;
        }
    }
    return HI_ERR_CERT_UNEXPECTED_EMI;
}

static hi_s32 __drv_cert_key_snd_ctl_impl(const hi_cert_key_data *key_ctl)
{
    hi_s32 ret;
    hi_u32 even;
    hi_u8 dsc_code = 0;
    akl_key_send_ctl reg;
    struct cert_mgmt *mgmt = __get_cert_mgmt();

    reg.u32 = 0;
    reg.bits.ds = key_ctl->sec_cfg.dest_buf_sec_support;
    reg.bits.dns = key_ctl->sec_cfg.dest_buf_non_sec_support;
    reg.bits.ss = key_ctl->sec_cfg.src_buf_sec_support;
    reg.bits.sns = key_ctl->sec_cfg.src_buf_non_sec_support;

    reg.bits.port_sel = __port_sel_gen(key_ctl->port_sel);

    reg.bits.send_start = 0x1;

    ret = __dsc_mode_gen(key_ctl->engine, &dsc_code);
    if (ret != HI_SUCCESS) {
        hi_err_cert("emi err %d!\n", key_ctl->engine);
        goto out;
    }

    even = (key_ctl->is_even == 0) ? 1 : 0;
    reg.bits.dsc_code = dsc_code;
    reg.bits.key_addr = (HI_HANDLE_GET_CHNID(key_ctl->handle) << 1) | even;

    ret = hal_cert_key_send_ctl(reg);
    if (ret != HI_SUCCESS) {
        hi_warn_cert("Cert send ctl err. reg=0x%x.\n", reg.u32);
        goto out;
    }

    ret = hal_cert_check_key_status();
    if (ret != HI_SUCCESS) {
        hi_warn_cert("cert check send status err.\n");
        goto out;
    }

out:
    mgmt->key_used = HI_TRUE;
    return ret;
}

static hi_s32 __drv_cert_key_snd_ctl(const hi_cert_key_data *key_ctl)
{
    hi_s32 ret;

    if (key_ctl->sec_cfg.key_secure) {
        hal_cert_set_sec_en();
    } else {
        hal_cert_set_sec_dis();
    }

    ret = __drv_cert_key_snd_ctl_impl(key_ctl);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_key_snd_ctl_impl, ret);
    }

    hal_cert_set_sec_dis();

    return ret;
}

static hi_s32 __drv_cert_metadata(hi_u32 *metadata)
{
    if (hal_cert_key_pending() != HI_TRUE) {
        return HI_ERR_CERT_NO_KEY_GENERATION;
    }
    *metadata = hal_cert_get_metadata();
    return HI_SUCCESS;
}

static hi_s32 _drv_cert_key_snd_ctl(hi_void *arg)
{
    hi_s32 ret;
    hi_cert_key_data *ctl = (hi_cert_key_data *)arg;

    if (arg == HI_NULL) {
        ret = HI_ERR_CERT_INVALID_PTR;
        goto out;
    }

    ret = __drv_cert_key_snd_ctl(ctl);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_key_snd_ctl, ret);
    }

out:
    return ret;
}

static hi_s32 _drv_cert_metadata(hi_void *arg)
{
    hi_s32 ret;
    hi_u32 *metadata = (hi_u32 *)arg;

    if (arg == HI_NULL) {
        return HI_ERR_CERT_INVALID_PTR;
    }
    ret = __drv_cert_metadata(metadata);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_metadata, ret);
    }
    return ret;
}

static inline hi_s32 __drv_cert_hw_lock(hi_void)
{
    hal_cert_lock();

    if (hal_cert_is_locked()) {
        return HI_SUCCESS;
    }
    return HI_FAILURE;
}

static inline hi_s32 __drv_cert_hw_unlock(hi_void)
{
    hal_cert_unlock();

    if (hal_cert_is_unlocked()) {
        return HI_SUCCESS;
    }
    return HI_FAILURE;
}

#define DELAY_MS 10
#define LOOP_NUM 1000

static hi_s32 _drv_cert_hw_lock(hi_void)
{
    hi_u32 time = LOOP_NUM;

    while (time--) {
        if (hal_cert_is_locked()) {
            msleep(DELAY_MS);
            continue;
        }
        if (__drv_cert_hw_lock() == HI_SUCCESS) {
            return HI_SUCCESS;
        }
        msleep(DELAY_MS);
    }
    return HI_ERR_CERT_TIMEOUT;
}

hi_s32 _drv_cert_hw_unlock(hi_void)
{
    hi_u32 time = LOOP_NUM;
    akl_data data = {{0}};

    hal_cert_set_data_in(&data);

    /*
    * Don't use hal_cert_is_unlocked, akl status include locked, unlocked, dead.
    * so locked not equal to ~unlocked.
    */
    if (!hal_cert_is_locked()) {
        return HI_ERR_CERT_UNLOCKED;
    }

    while (time--) {
        if (__drv_cert_hw_unlock() == HI_SUCCESS) {
            return HI_SUCCESS;
        }
        msleep(DELAY_MS);
    }
    return HI_ERR_CERT_TIMEOUT;
}

static hi_s32 __drv_cert_lock(hi_cert_res_handle *handle)
{
    hi_u32 ret;

    struct cert_mgmt *mgmt = __get_cert_mgmt();

    ret = _drv_cert_hw_lock();
    if (ret != HI_SUCCESS) {
        print_err_func(_drv_cert_hw_lock, ret);
        return ret;
    }
    ret = hi_tee_drv_hal_current_uuid(&mgmt->owner);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_tee_drv_hal_current_uuid, ret);
        return ret;
    }

    hi_dbg_cert("lock mgmt.owner=0x%08x.\n", &mgmt->owner);

    handle->res_handle = (hi_handle)&mgmt->owner;

    mgmt->key_used = HI_FALSE;

    /* if key pending on the bus, clear key. */
    if (hal_cert_key_pending()) {
        hal_cert_key_send();
    }
    return HI_SUCCESS;
}

static hi_s32 __drv_cert_unlock(hi_cert_res_handle *handle)
{
    hi_s32 ret;
    TEE_UUID cur_uuid = {0};

    ret = hi_tee_drv_hal_current_uuid(&cur_uuid);
    if (ret != HI_SUCCESS) {
        print_err_func(hi_tee_drv_hal_current_uuid, ret);
        return ret;
    }

    ret = memcmp((TEE_UUID *)handle->res_handle, &cur_uuid, sizeof(TEE_UUID));
    if (ret != EOK) {
        hi_err_cert("Invalid Key Handle 0x%x\n", handle->res_handle);
        return HI_ERR_KLAD_INVALID_HANDLE;
    }

    ret = _drv_cert_hw_unlock();
    if (ret != HI_SUCCESS) {
        print_err_func(_drv_cert_hw_unlock, ret);
        return ret;
    }

    handle->res_handle = 0;
    return HI_SUCCESS;
}

static hi_s32 _drv_cert_lock(hi_void *arg)
{
    hi_s32 ret;
    hi_cert_res_handle *attr = (hi_cert_res_handle *)arg;

    if (arg == HI_NULL) {
        return HI_ERR_CERT_INVALID_PTR;
    }
    ret = __drv_cert_lock(attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_lock, ret);
    }
    return ret;
}

static hi_s32 _drv_cert_unlock(hi_void *arg)
{
    hi_s32 ret;
    hi_cert_res_handle *attr = (hi_cert_res_handle *)arg;

    if (arg == HI_NULL) {
        return HI_ERR_CERT_INVALID_PTR;
    }
    ret = __drv_cert_unlock(attr);
    if (ret != HI_SUCCESS) {
        print_err_func(__drv_cert_unlock, ret);
    }
    return ret;
}

static hi_void __drv_cert_reset(hi_void)
{
    hal_cert_reset();

    __drv_cert_sec_init();
}

hi_s32 _drv_cert_reset(hi_void *arg)
{
    __drv_cert_reset();

    return HI_SUCCESS;
}

static cert_ioctl_node g_ioctl_func_map[] = {
    { CMD_CERT_AKLEXCHANGE,         _drv_cert_exchange },
    { CMD_CERT_AKLKEYSEND_CTL,      _drv_cert_key_snd_ctl },
    { CMD_CERT_METADATA,            _drv_cert_metadata },
    { CMD_CERT_LOCK,                _drv_cert_lock },
    { CMD_CERT_UNLOCK,              _drv_cert_unlock },
    { CMD_CERT_RESET,               _drv_cert_reset },
    { CMD_CERT_MAX,                HI_NULL},
};

hi_s32 cert_ioctl_impl(hi_u32 cmd, hi_void *arg, hi_u32 len)
{
    hi_s32 ret = HI_ERR_CERT_UNKNOWN_CMD;
    hi_s32 size;
    cert_ioctl_node *node = HI_NULL_PTR;

    _cert_mutex_lock();

    for (size = 0, node = &g_ioctl_func_map[0];
         size < sizeof(g_ioctl_func_map) / sizeof(g_ioctl_func_map[0]);
         size++, node = &g_ioctl_func_map[size]) {
        if (node->cmd != cmd) {
            continue;
        }
        if (node->fun_ioctl != HI_NULL) {
            ret = node->fun_ioctl(arg);
        } else {
            ret = HI_ERR_CERT_INVALID_PTR;
        }
        goto out;
    }

out:
    _cert_mutex_unlock();
    return ret;
}

hi_s32 hi_drv_cert_init(hi_void)
{
    hi_s32 ret;

    _cert_mutex_lock();

    ret = __drv_cert_init();

    _cert_mutex_unlock();
    return ret;
}
export_symbol(hi_drv_cert_init);

hi_s32 hi_drv_cert_deinit(hi_void)
{
    _cert_mutex_lock();

    __drv_cert_deinit();

    _cert_mutex_unlock();
    return HI_SUCCESS;
}
export_symbol(hi_drv_cert_deinit);

hi_s32 hi_drv_cert_reset(hi_void)
{
    _cert_mutex_lock();

    __drv_cert_reset();

    _cert_mutex_unlock();
    return HI_SUCCESS;
}
export_symbol(hi_drv_cert_reset);

hi_s32 hi_drv_cert_lock(hi_cert_res_handle *handle)
{
    hi_s32 ret;

    _cert_mutex_lock();

    ret = __drv_cert_lock(handle);

    _cert_mutex_unlock();
    return ret;
}
export_symbol(hi_drv_cert_lock);

hi_s32 hi_drv_cert_unlock(hi_cert_res_handle *handle)
{
    hi_s32 ret;

    _cert_mutex_lock();

    ret = __drv_cert_unlock(handle);

    _cert_mutex_unlock();
    return ret;
}
export_symbol(hi_drv_cert_unlock);

hi_s32 hi_drv_cert_exchange(hi_cert_res_handle *handle, hi_cert_command *cmd)
{
    hi_s32 ret;

    _cert_mutex_lock();

    ret = __drv_cert_exchange(handle, cmd);

    _cert_mutex_unlock();
    return ret;
}
export_symbol(hi_drv_cert_exchange);

hi_s32 hi_drv_cert_key_snd_ctl(hi_cert_key_data *ctl)
{
    hi_s32 ret;

    _cert_mutex_lock();

    ret = __drv_cert_key_snd_ctl(ctl);

    _cert_mutex_unlock();
    return ret;
}
