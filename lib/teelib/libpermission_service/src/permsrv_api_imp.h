/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: permission service implementation
 * Create: 2018-05-18
 */
#ifndef __PERSRV_API_IMP_H__
#define __PERSRV_API_IMP_H__

#include "permission_service.h"

#define HASH_FILE_MAX_SIZE (64 * 1024)
#define PERMSRV_FILE_OPT ".rtosck.permsrv_file_operation"

int perm_srv_msg_call(const char *path, perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp);

void tee_perm_init_msg(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg);

TEE_Result rslot_file_msg_call(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg);

TEE_Result get_permission_by_type(const TEE_UUID *uuid, uint32_t taskid, uint32_t checkby, uint32_t type,
                                  perm_srv_permsrsp_t *result);

void permsrv_registerta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id, uint32_t opt_type);

TEE_Result tee_cert_import(const uint8_t *cert_buf, uint32_t cert_size, const uint8_t *pub_key, uint32_t pub_key_size);

TEE_Result tee_ta_ctrl_list_process(const uint8_t *ctrl_list, uint32_t ctrl_list_size);

void permsrv_notify_unload_ta(const TEE_UUID *uuid);

void permsrv_load_file();

TEE_Result permsrv_elf_verify(const void *verify_req, uint32_t len);

TEE_Result permsrv_crt_export(uint8_t *dst, uint32_t *len, uint32_t limit);

TEE_Result permsrv_crt_remove(void);
#endif /* __PERSRV_API_IMP_H__ */
