/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: perm service do elf verify
 * Author: lipeng
 * Create: 2021-08-11
 */
#ifndef HANDLE_ELF_VERIFY_H
#define HANDLE_ELF_VERIFY_H

#include <tee_defines.h>
#include "permission_service.h"

#define TA_SO_TARGET_TYPE ((enum target_type)0xff)

TEE_Result perm_serv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr);
#endif
