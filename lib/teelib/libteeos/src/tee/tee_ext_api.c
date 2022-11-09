/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "tee_ext_api.h"
#include <securec.h>
#include "msg_ops.h"
#include "tee_config.h"
#include "tee_log.h"
#include "tee_init.h"

/*
 * below APIs are defined by Platform SDK released previously
 * for compatibility:
 * don't change function name / return value type / parameters types / parameters names
 */
uint32_t get_die_id_size(void)
{
    return INVALID_DIE_ID_SIZE;
}

TEE_Result tee_ext_get_caller_info(caller_info *caller_info_data, uint32_t length)
{
    caller_info ret_info = { 0 };
    errno_t rc;
    uint32_t ret;

    if (caller_info_data == NULL) {
        tloge("invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* for compatibility in this situation: update caller_info struct in the future */
    if (length < (sizeof(ret_info.caller_identity.caller_uuid) + sizeof(ret_info.session_type))) {
        tloge("input length is %u too short\n", length);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = ipc_msg_snd(TA_GET_CALLERINFO, get_global_handle(), NULL, 0);
    if (ret != TEE_SUCCESS) {
        tloge("send msg failed in get callerinfo, ret=0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    ret = ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, &ret_info, sizeof(ret_info), get_global_handle());
    if (ret != TEE_SUCCESS) {
        tloge("receive msg failed in get caller info, ret=0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    if (ret_info.session_type != SESSION_FROM_UNKNOWN) {
        rc = memcpy_s(&caller_info_data->caller_identity.caller_uuid,
                      sizeof(caller_info_data->caller_identity.caller_uuid), &ret_info.caller_identity.caller_uuid,
                      sizeof(ret_info.caller_identity.caller_uuid));
        if (rc != EOK) {
            tloge("copy data failed\n");
            return TEE_ERROR_SECURITY;
        }

        caller_info_data->session_type = ret_info.session_type;
        caller_info_data->smc_from_kernel_mode = ret_info.smc_from_kernel_mode;
    } else {
        tloge("Failed to get caller info\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

uint32_t tee_get_session_type(void)
{
    return get_current_session_type();
}
