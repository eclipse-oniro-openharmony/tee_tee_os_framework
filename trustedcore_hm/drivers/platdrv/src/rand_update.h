/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: update random
 * Create: 2021-08
 */
#ifndef RAND_UPDATE_H
#define RAND_UPDATE_H
#include <stdint.h>

#include <errno.h>
#include <sys/usrsyscall_new_ext.h>
#include <hm_msg_type.h>
#include <sys/hm_types.h>

intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);
#endif
