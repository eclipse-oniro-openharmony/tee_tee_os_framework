/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: klad TA
 * Author: linux SDK team
 * Create: 2019-07-23
 */

#include "hi_tee_hal.h"
#include "hi_tee_klad.h"
#include "hi_tee_log.h"
#include "hi_tee_module_id.h"

#define unused(x) ((x) = (x))

#define CMD_KLAD_INIT                       0x10
#define CMD_KLAD_DEINIT                     0x11
#define CMD_KLAD_CREATE                     0x1
#define CMD_KLAD_DESTORY                    0x2
#define CMD_KLAD_ATTACH                     0x3
#define CMD_KLAD_DETACH                     0x4
#define CMD_KLAD_GET_ATTR                   0x5
#define CMD_KLAD_SET_ATTR                   0x6
#define CMD_RK_GET_ATTR                     0x25
#define CMD_RK_SET_ATTR                     0x26
#define CMD_KLAD_SET_SESSION_KEY            0x7
#define CMD_KLAD_SET_CONTENT_KEY            0x9
#define CMD_KLAD_ASYNC_SET_CONTENT_KEY      0x19
#define CMD_KLAD_SET_CLEAR_KEY              0xa
#define CMD_KLAD_GET_NONCE_KEY              0xb

#define CMD_API_LOG_LEVEL                   0xfe
#define CMD_KLAD_LOG_LEVEL                  0xFF

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

hi_char g_user_data[0x10] = {0};

hi_s32 klad_call_back(hi_s32 err_code, hi_char *args, hi_u32 size, hi_void *user_data, hi_u32 user_data_len)
{
    printf("----------ret 0x%x-----%p---------\n", err_code, user_data);
    unused(args);
    unused(size);
    unused(user_data_len);
    return 0;
}

int32_t klad_test(uint32_t cmd_id, uint32_t param_types, TEE_Param params[0x4])
{
    int32_t ret = HI_SUCCESS;
    hi_tee_klad_done_callback call_back_func;

    unused(param_types);
    switch (cmd_id) {
        case  CMD_KLAD_INIT:
            return hi_tee_klad_init();
        case  CMD_KLAD_CREATE:
            return hi_tee_klad_create(params[0].memref.buffer);
        case  CMD_KLAD_ATTACH:
            return hi_tee_klad_attach(params[0].value.a, params[0].value.b);
        case  CMD_KLAD_DETACH:
            return hi_tee_klad_detach(params[0].value.a, params[0].value.b);
        case  CMD_KLAD_SET_ATTR:
            return hi_tee_klad_set_attr(params[0].value.a, params[1].memref.buffer);
        case  CMD_KLAD_GET_ATTR:
            return hi_tee_klad_get_attr(params[0].value.a, params[1].memref.buffer);
        case  CMD_RK_GET_ATTR:
            return hi_tee_klad_get_root_key_attr(params[0].value.a, params[1].memref.buffer);
        case  CMD_RK_SET_ATTR:
            return hi_tee_klad_set_root_key_attr(params[0].value.a, params[1].memref.buffer);
        case  CMD_KLAD_SET_CLEAR_KEY:
            return hi_tee_klad_set_clear_key(params[0].value.a, params[1].memref.buffer);
        case  CMD_KLAD_SET_SESSION_KEY:
            return hi_tee_klad_set_session_key(params[0].value.a, params[1].memref.buffer);
        case  CMD_KLAD_SET_CONTENT_KEY:
            return hi_tee_klad_set_content_key(params[0].value.a, params[1].memref.buffer);
        case  CMD_KLAD_ASYNC_SET_CONTENT_KEY:
            call_back_func.done_callback = klad_call_back;
            call_back_func.user_data = g_user_data;
            call_back_func.user_data_len = sizeof(g_user_data);
            return hi_tee_klad_async_set_content_key(params[0].value.a, params[1].memref.buffer, &call_back_func);
        case  CMD_KLAD_DESTORY:
            return hi_tee_klad_destroy(params[0].value.a);
        case  CMD_KLAD_DEINIT:
            return hi_tee_klad_deinit();
        case CMD_KLAD_LOG_LEVEL:
            tloge("set klad log level[0x%x]\n", params[0].value.a);
            return hi_tee_log_set_level(HI_ID_KLAD, params[0].value.a);
        case CMD_API_LOG_LEVEL:
            tloge("set api log level[0x%x]\n", params[0].value.a);
            return hi_tee_log_set_level(HI_ID_USR, params[0].value.a);
        default:
            ret = TEE_ERROR_BAD_PARAMETERS;
            break;
    }
    return ret;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *session_context, uint32_t cmd_id,
                                                uint32_t param_types, TEE_Param params[0x4])
{
    TEE_Result ret;

    unused(session_context);

    ret = klad_test(cmd_id, param_types, params);
    if (ret != TEE_SUCCESS) {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", cmd_id, ret);
    }
    return  ret;
}

__DEFAULT hi_void TA_CloseSessionEntryPoint(hi_void *session_context)
{
    unused(session_context);
}

__DEFAULT hi_void TA_DestroyEntryPoint(hi_void)
{
    return;
}
