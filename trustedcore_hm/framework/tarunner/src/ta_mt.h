/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: TA work thread function.
 * Create: 2019-06-03
 */
#ifndef TA_MT_TA_MT_H
#define TA_MT_TA_MT_H

#include <stdint.h>
#include <ta_routine.h> /* for ta_routine_info */

#define INIT_BUILD 0
#define NON_INIT_BUILD 1

#define SECOND_CHANNEL 1
#define DEFAULT_MSG_HANDLE 0
#define CREATE_THREAD_FAIL 0xFFFFFFFFU /* same to gtask */
#define TADUMP_FOR_LIBFUZZER 0xFFFA
void tee_task_entry_mt(ta_entry_type ta_entry, uint32_t ca, int32_t priority, const char *name,
    const struct ta_routine_info *append_args);

#endif
