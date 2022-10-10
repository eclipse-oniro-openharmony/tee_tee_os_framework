/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: perm service do ca hashfile verify
 * Author: liangshan
 * Create: 2022-04-14
 */
#ifndef HANDLE_CA_HASHFILE_VERIFY_H
#define HANDLE_CA_HASHFILE_VERIFY_H

#include <tee_defines.h>
#include "permission_service.h"

TEE_Result perm_serv_ca_hashfile_verify(perm_srv_reply_msg_t *rsp, const perm_srv_req_msg_t *msg, uint32_t sender);

#endif