/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: otp TA
 * Author: linux SDK team
 * Create: 2019-07-23
 */

#include "hi_tee_hal.h"
#include "hi_tee_log.h"
#include "hi_tee_otp.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_ioctl_otp.h"

#define CMD_OTP_PROCESS 0xF140

#define unused(x) ((x) = (x))

typedef enum {
    OTP_CMD_READ_WORD = 0x01,
    OTP_CMD_READ_BYTE,
    OTP_CMD_WRITE_BYTE,
    OTP_CMD_GET_TAID_AND_MSID,
    OTP_CMD_SET_TAID_AND_MSID,
    OTP_CMD_GET_CHIP_ID,
    OTP_CMD_GET_CA_CHIP_ID,
    OTP_CMD_SET_ROOT_KEY,
    OTP_CMD_GET_ROOT_KEY_LOCK_STAT,
    OTP_CMD_SET_ROOT_KEY_SLOT_FLAG,
    OTP_CMD_GET_ROOT_KEY_SLOT_FLAG,
    OTP_CMD_GET_SEC_VERSION,
    OTP_CMD_SET_TA_CERTIFICATE_VERSION,
    OTP_CMD_GET_TA_CERTIFICATE_VERSION,
    OTP_CMD_SET_TA_SECURE_VERSION,
    OTP_CMD_GET_TA_SECURE_VERSION,
    OTP_CMD_GET_TA_INDEX,
    OTP_CMD_GET_AVAILABLE_TA_INDEX,
    OTP_CMD_GET_PRIV_DRM_DATA,
    OTP_CMD_SET_PRIV_DRM_DATA,
    OTP_CMD_TEST,
    OTP_CMD_LOG_LEVEL,
    OTP_CMD_GET_RUNTIME_CHECK_STAT,
    OTP_CMD_ENABLE_RUNTIME_CHECK,
} tee_otp_cmd;

#define print_err_hex(val)               tloge("%s = 0x%08x\n", #val, val)
#define print_err_hex2(x, y)             tloge("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)          tloge("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)       tloge("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                                     w, #x, x, #y, y, #z, z)
#define print_err_func_hex(func, val)    tloge("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_err_func_hex2(func, x, y)  tloge("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_err_func_hex3(func, x, y, z) \
    tloge("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_err_func_hex4(func, w, x, y, z) \
    tloge("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define print_err_val(val)               tloge("%s = %d\n", #val, val)
#define print_err_point(val)             tloge("%s = %p\n", #val, val)
#define print_err_code(err_code)         tloge("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)   tloge("call [%s] return [0x%08x]\n", #func, err_code)

typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_ioctl)(TEE_Param params[0x4]);
} cmd_otp_node;

static hi_s32 __otp_cmd_test(hi_u32 cmd, otp_test_data *test_data)
{
    hi_u32 ret;
    hi_u32 args[] = {
        cmd,
        (hi_u32)(uintptr_t)test_data,
    };

    ret = hm_drv_call(CMD_OTP_PROCESS, args, ARRAY_SIZE(args));
    if (ret != HI_SUCCESS) {
        print_err_hex4(ARRAY_SIZE(args), cmd, (unsigned int)(uintptr_t)test_data, ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 _otp_log_level(TEE_Param params[0x4])
{
    hi_s32 ret;

    tloge("set otp log level[0x%x]\n", params[0].value.a);
    ret =  hi_tee_log_set_level(HI_ID_OTP, params[0].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_log_set_level, params[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_read_word(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_read_word(params[0].value.a, &params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_read_word, params[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_read_byte(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_read_byte(params[0].value.a, (hi_u8 *)&params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_read_byte, params[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_write_byte(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_write_byte(params[0].value.a, params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_write_byte, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_taid_and_msid(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_taid_and_msid(params[0].value.a, &params[0x1].value.a, &params[0x1].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex3(hi_tee_otp_get_taid_and_msid, params[0].value.a,
                            params[0x1].value.a, params[0x1].value.b);
    }

    return ret;
}

static hi_s32 _otp_set_taid_and_msid(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_set_taid_and_msid(params[0].value.a, params[0x1].value.a, params[0x1].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex3(hi_tee_otp_set_taid_and_msid, params[0].value.a,
                            params[0x1].value.a, params[0x1].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_chip_id(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_chip_id(params[0].memref.buffer, &params[1].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_get_chip_id, ret);
    }

    return ret;
}

static hi_s32 _otp_get_ca_chip_id(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_ca_chip_id(params[0].value.a, params[0x1].memref.buffer, &params[0x2].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_ca_chip_id, params[0].value.a, params[0x2].value.a);
    }

    return ret;
}

static hi_s32 _otp_set_root_key(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_set_root_key(params[0].value.a, params[0x1].memref.buffer, params[0x2].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_set_root_key, params[0].value.a, params[0x2].value.a);
    }

    return ret;
}

static hi_s32 _otp_get_root_key_lock_stat(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_root_key_lock_stat(params[0].value.a, (hi_bool *)&params[0x1].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_root_key_lock_stat, params[0].value.a, params[0x1].value.a);
    }

    return ret;
}

static hi_s32 _otp_set_root_key_slot_flag(TEE_Param params[0x4])
{
    hi_s32 ret;
    TEE_Param *data = params;

    ret = hi_tee_otp_set_root_key_slot_flag(data[0].value.a, data[0x1].memref.buffer);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_set_root_key_slot_flag, data[0].value.a);
    }

    return ret;
}


static hi_s32 _otp_get_root_key_slot_flag(TEE_Param params[0x4])
{
    hi_s32 ret;
    TEE_Param *data = params;

    ret = hi_tee_otp_get_root_key_slot_flag(data[0].value.a, data[0x1].memref.buffer);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_get_root_key_slot_flag, data[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_get_sec_version(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_sec_version(&params[0].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_get_sec_version, params[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_set_ta_cert_version(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_set_ta_certificate_version(params[0].value.a, params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_set_ta_certificate_version, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_ta_cert_version(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_ta_certificate_version(params[0].value.a, &params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_ta_certificate_version, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_set_ta_sec_version(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_set_ta_secure_version(params[0].value.a, params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_set_ta_secure_version, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_ta_sec_version(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_ta_secure_version(params[0].value.a, &params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_ta_secure_version, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_ta_index(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_ta_index(params[0].value.a, &params[0].value.b);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_ta_index, params[0].value.a, params[0].value.b);
    }

    return ret;
}

static hi_s32 _otp_get_available_ta_index(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_available_ta_index(&params[0].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_get_available_ta_index, params[0].value.a);
    }

    return ret;
}

static hi_s32 _otp_set_priv_drm_data(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_set_priv_drm_data(params[0].value.a, (hi_u8 *)params[1].memref.buffer, params[0x2].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_set_priv_drm_data, params[0].value.a, params[0x2].value.a);
    }

    return ret;
}

static hi_s32 _otp_get_priv_drm_data(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_priv_drm_data(params[0].value.a, (hi_u8 *)params[1].memref.buffer, &params[0x2].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_priv_drm_data, params[0].value.a, params[0x2].value.a);
    }

    return ret;
}

static hi_s32 _otp_cmd(TEE_Param params[0x4])
{
    hi_s32 ret = HI_FAILURE;
    otp_test_data otp_test = {0};

    if (memcpy_s(otp_test.reserved, sizeof(otp_test.reserved),
                 params[0x1].memref.buffer, params[0x1].memref.size) != EOK) {
        print_err_func_hex2(memcpy_s, sizeof(otp_test.reserved), params[0x1].memref.size);
        return ret;
    }
    ret = __otp_cmd_test(params[0].value.a, &otp_test);

    return ret;
}

static hi_s32 _otp_get_runtime_check_stat(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_get_runtime_check_stat((hi_bool *)&params[0].value.a);
    if (ret != HI_SUCCESS) {
        print_err_func_hex2(hi_tee_otp_get_priv_drm_data, params[0].value.a, ret);
    }

    return ret;
}

static hi_s32 _otp_enable_runtime_check(TEE_Param params[0x4])
{
    hi_s32 ret;

    ret = hi_tee_otp_enable_runtime_check();
    if (ret != HI_SUCCESS) {
        print_err_func_hex(hi_tee_otp_get_priv_drm_data, ret);
    }

    unused(params);
    return ret;
}

static cmd_otp_node g_cmd_func_map[] = {
    { OTP_CMD_LOG_LEVEL,                   _otp_log_level },
    { OTP_CMD_READ_WORD,                   _otp_read_word },
    { OTP_CMD_READ_BYTE,                   _otp_read_byte },
    { OTP_CMD_WRITE_BYTE,                  _otp_write_byte },
    { OTP_CMD_GET_TAID_AND_MSID,           _otp_get_taid_and_msid },
    { OTP_CMD_SET_TAID_AND_MSID,           _otp_set_taid_and_msid },
    { OTP_CMD_GET_CHIP_ID,                 _otp_get_chip_id },
    { OTP_CMD_GET_CA_CHIP_ID,              _otp_get_ca_chip_id },
    { OTP_CMD_SET_ROOT_KEY,                _otp_set_root_key },
    { OTP_CMD_GET_ROOT_KEY_LOCK_STAT,      _otp_get_root_key_lock_stat },
    { OTP_CMD_SET_ROOT_KEY_SLOT_FLAG,      _otp_set_root_key_slot_flag },
    { OTP_CMD_GET_ROOT_KEY_SLOT_FLAG,      _otp_get_root_key_slot_flag },
    { OTP_CMD_GET_SEC_VERSION,             _otp_get_sec_version },
    { OTP_CMD_SET_TA_CERTIFICATE_VERSION,  _otp_set_ta_cert_version },
    { OTP_CMD_GET_TA_CERTIFICATE_VERSION,  _otp_get_ta_cert_version },
    { OTP_CMD_SET_TA_SECURE_VERSION,       _otp_set_ta_sec_version },
    { OTP_CMD_GET_TA_SECURE_VERSION,       _otp_get_ta_sec_version },
    { OTP_CMD_GET_TA_INDEX,                _otp_get_ta_index },
    { OTP_CMD_GET_AVAILABLE_TA_INDEX,      _otp_get_available_ta_index },
    { OTP_CMD_SET_PRIV_DRM_DATA,           _otp_set_priv_drm_data },
    { OTP_CMD_GET_PRIV_DRM_DATA,           _otp_get_priv_drm_data },
    { OTP_CMD_TEST,                        _otp_cmd },
    { OTP_CMD_GET_RUNTIME_CHECK_STAT,      _otp_get_runtime_check_stat },
    { OTP_CMD_ENABLE_RUNTIME_CHECK,        _otp_enable_runtime_check },
};

__DEFAULT TEE_Result TA_CreateEntryPoint(hi_void)
{
    AddCaller_CA_exec("default", 0);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[0x4], hi_void **session_context)
{
    unused(param_types);
    unused(params);
    unused(session_context);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *session_context, uint32_t cmd_id,
                                                uint32_t param_types, TEE_Param params[0x4])
{
    TEE_Result result = TEE_SUCCESS;
    hi_s32 ret = HI_FAILURE;
    hi_u32 size;
    cmd_otp_node *node = HI_NULL;

    for (size = 0, node = &g_cmd_func_map[0];
         size < sizeof(g_cmd_func_map) / sizeof(g_cmd_func_map[0]);
         size++, node = &g_cmd_func_map[size]) {
        if (node->cmd != cmd_id) {
            continue;
        }
        if (node->fun_ioctl != HI_NULL) {
            ret = node->fun_ioctl(params);
        } else {
            ret = HI_FAILURE;
        }
        goto out;
    }

    unused(param_types);
    unused(params);
    unused(session_context);
out:
    if (ret != HI_SUCCESS) {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", cmd_id, ret);
        result = TEE_ERROR_BAD_PARAMETERS;
    }

    return result;
}

__DEFAULT hi_void TA_CloseSessionEntryPoint(hi_void *session_context)
{
    unused(session_context);
}

__DEFAULT hi_void TA_DestroyEntryPoint(hi_void)
{
    return;
}
