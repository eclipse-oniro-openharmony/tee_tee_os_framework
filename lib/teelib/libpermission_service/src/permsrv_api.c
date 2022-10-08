/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: permission service implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
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

TEE_Result tee_ext_ca_hashfile_verify(const uint8_t *buf, uint32_t size)
{
    if (buf == NULL || size == 0) {
        tloge("params is invaild\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return permsrv_ca_hashfile_verfiy(buf, size);
}
