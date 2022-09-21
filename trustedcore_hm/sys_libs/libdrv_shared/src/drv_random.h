/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: declare funtion send msg to driver process
 * Create: 2022-01-01
 */
#ifndef DRVMGR_SRC_DRV_RANDOM_H
#define DRVMGR_SRC_DRV_RANDOM_H

#include <stdint.h>
#include <tee_defines.h>
#include "hm_msg_type.h"
#include <errno.h>
#include <sys/usrsyscall_new_ext.h>
#include <hm_msg_type.h>
#include <sys/hm_types.h>

typedef int32_t (*crypto_drv_init) (const void *ops, void *buf, uint32_t buf_len);
void register_crypto_rand_driver(crypto_drv_init fun, void *ops);
intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);
#endif
