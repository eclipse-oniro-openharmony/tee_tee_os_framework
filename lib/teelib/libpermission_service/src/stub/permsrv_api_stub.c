/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permission service implementation stub
 * Create: 2022-04-01
 */
#include "tee_ext_api.h"
#include "tee_log.h"
#include "permsrv_api.h"

TEE_Result tee_ext_ca_hashfile_verify(const uint8_t *buf, uint32_t size)
{
    (void)buf;
    (void)size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_crl_update(const uint8_t *buffer, uint32_t size)
{
    (void)buffer;
    (void)size;
    return TEE_ERROR_NOT_SUPPORTED;
}

void tee_ext_register_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    (void)uuid;
    (void)task_id;
    (void)user_id;
    return;
}

void tee_ext_unregister_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    (void)uuid;
    (void)task_id;
    (void)user_id;
    return;
}

void tee_ext_notify_unload_ta(const TEE_UUID *uuid)
{
    (void)uuid;
    return;
}

void tee_ext_load_file(void)
{
    return;
}

TEE_Result tee_ext_get_sfs_capability(const TEE_UUID *uuid, uint64_t *result)
{
    (void)uuid;
    (void)result;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_get_se_capability(const TEE_UUID *uuid, uint64_t *result)
{
    (void)uuid;
    (void)result;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size)
{
    (void)crl_cert;
    (void)crl_cert_size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_ta_ctrl_list_process(const char *ctrl_list, uint32_t ctrl_list_size)
{
    (void)ctrl_list;
    (void)ctrl_list_size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_get_manage_info(const TEE_UUID *uuid, uint32_t *manager)
{
    (void)uuid;
    (void)manager;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_elf_verify_req(const void *req, uint32_t len)
{
    (void)req;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}
