/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: TA work thread function.
 * Create: 2019-05-18
 */

#ifndef TARUNNER_MAIN_H
#define TARUNNER_MAIN_H

#include <sys/usrsyscall_ext.h>

/* __tcb_cref and __sysmgrch are from assembly, cannot remove extern */
extern cref_t __tcb_cref;
extern cref_t __sysmgrch;

#endif