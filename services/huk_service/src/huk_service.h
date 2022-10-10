/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: huk service implementation
 * Author: lilianhui1@huawei.com
 * Create: 2020-12-14
 */
#ifndef HUK_SERVICE_H
#define HUK_SERVICE_H
void handle_huk_cmd(union ssa_agent_msg *msg, uint32_t sndr_pid, struct ssa_agent_rsp *rsp);
#endif
