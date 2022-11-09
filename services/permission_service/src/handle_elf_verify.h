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
#ifndef HANDLE_ELF_VERIFY_H
#define HANDLE_ELF_VERIFY_H

#include <tee_defines.h>
#include "permission_service.h"

#define TA_SO_TARGET_TYPE ((enum target_type)0xff)

TEE_Result perm_serv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr);
#endif
