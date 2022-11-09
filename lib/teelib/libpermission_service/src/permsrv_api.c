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
#include "tee_log.h"
#include "permsrv_api.h"
#include "permsrv_api_imp.h"
/* follow function for global task */

void tee_ext_register_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    if (uuid == NULL) {
        tloge("register TA with NULL uuid\n");
        return;
    }

    permsrv_registerta(uuid, task_id, user_id, REGISTER_TA);
}

void tee_ext_unregister_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    if (uuid == NULL) {
        tloge("unregister TA with NULL uuid\n");
        return;
    }

    permsrv_registerta(uuid, task_id, user_id, UNREGISTER_TA);
}

void tee_ext_notify_unload_ta(const TEE_UUID *uuid)
{
    if (uuid == NULL) {
        tloge("uuid is NULL.\n");
        return;
    }
    permsrv_notify_unload_ta(uuid);
}

void tee_ext_load_file(void)
{
    permsrv_load_file();
}

TEE_Result tee_ext_get_se_capability(const TEE_UUID *uuid, uint64_t *result)
{
    TEE_Result res;
    if (result == NULL || uuid == NULL) {
        tloge("get se capability bad parameter");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    perm_srv_permsrsp_t response = { 0 };

    res = get_permission_by_type(uuid, 0, CHECK_BY_UUID, PERM_TYPE_SE_CAPABILITY, &response);

    *result = response.se_capability;

    return res;
}

TEE_Result tee_ext_ta_ctrl_list_process(const char *ctrl_list, uint32_t ctrl_list_size)
{
    TEE_Result ret;

    if (ctrl_list == NULL) {
        tloge("ta ctrl list process bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ctrl_list_size == 0) {
        tloge("TEE_EXT_Set_Config bad parameter, size error!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = tee_ta_ctrl_list_process((uint8_t *)ctrl_list, ctrl_list_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to do crl cert process\n");
        return ret;
    }

    return ret;
}

TEE_Result tee_ext_elf_verify_req(const void *req, uint32_t len)
{
    return permsrv_elf_verify(req, len);
}
