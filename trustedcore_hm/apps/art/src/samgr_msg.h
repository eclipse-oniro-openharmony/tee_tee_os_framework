/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: samgr msg communication management.
 * Author: x00225909
 * Create: 2020-07-02
 */
#ifndef _SAMGR_MSG_H_
#define _SAMGR_MSG_H_

#include "tee_service_public.h"
#include <stdint.h>

/*
 * @brief     : load sa.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_load_sa(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);

/*
 * @brief     : get sa status.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_get_sa_status(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);

/*
 * @brief     : install sa.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_install_sa(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp);

#endif
