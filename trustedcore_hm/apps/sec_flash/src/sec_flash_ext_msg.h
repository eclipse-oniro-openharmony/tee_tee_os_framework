/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash msg ext API communication management.
 * Author: lvtaolong
 * Create: 2019-10-15
 * Notes:
 * History: 2019-10-15 lvtaolong create
 *          2019-10-15 chengruhong add secflash_ext_call_xxx functions.
 */
#ifndef _SEC_FLASH_EXT_MSG_H_
#define _SEC_FLASH_EXT_MSG_H_

#include "tee_service_public.h"

void secflash_ext_call_is_available(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);
void secflash_ext_call_factory_recovery(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);
void secflash_ext_call_power_saving(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);
void secflash_ext_call_device_reset(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);
void secflash_ext_call_derive_binding_key(const tee_service_ipc_msg *msg,
                                          uint32_t sender, tee_service_ipc_msg_rsp *rsp);
void secflash_ext_call_writelock_cfg(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);
#endif
