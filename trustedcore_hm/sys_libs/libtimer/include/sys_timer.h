/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: moved from teeos, timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_SYS_TIMER_H
#define LIBTIMER_SYS_TIMER_H

#include <dlist.h>
#include <limits.h>
#include <sre_errno.h>
#include <hm_msg_type.h>
#include <tee_time_defines.h>

void release_timer_event(const TEE_UUID *uuid);
#endif
