/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: permsrv api interface head file
 * Create: 2018-12-12
 * History: 2020-09-03 limingjuan limingjuan@huawei.com modify qis warning
 */

#ifndef __PERSRV_API_H__
#define __PERSRV_API_H__

#include "tee_defines.h"
#include "permsrv_api_legacy.h"

enum TaManager {
    TA_MANAGER_UNKNOWN,
    TA_MANAGER_TRUSTONIC
};

void tee_ext_register_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id);
void tee_ext_unregister_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id);
void tee_ext_notify_unload_ta(const TEE_UUID *uuid);
void tee_ext_load_file(void);

TEE_Result tee_ext_get_sfs_capability(const TEE_UUID *uuid, uint64_t *result);
TEE_Result tee_ext_get_se_capability(const TEE_UUID *uuid, uint64_t *result);
TEE_Result tee_ext_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size);
TEE_Result tee_ext_ta_ctrl_list_process(const char *ctrl_list, uint32_t ctrl_list_size);
TEE_Result tee_ext_get_manage_info(const TEE_UUID *uuid, uint32_t *manager);
TEE_Result tee_ext_elf_verify_req(const void *req, uint32_t len);
TEE_Result tee_ext_crl_update(const uint8_t *buffer, uint32_t size);
TEE_Result tee_ext_ca_hashfile_verify(const uint8_t *buf, uint32_t size);
#endif
