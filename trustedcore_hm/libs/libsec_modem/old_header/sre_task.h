/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: old header reserved for modem
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-06-11
 */
#ifndef LIBSEC_MODEM_OLD_HEADER_SRE_TASK_H
#define LIBSEC_MODEM_OLD_HEADER_SRE_TASK_H
#include "sre_base.h"

typedef void (*TSK_ENTRY_FUNC)(uint32_t param1, uint32_t param2, uint32_t param3, uint32_t param4);

typedef int32_t (*DEV_RELEASE_CALLBACK)(void *data);

#endif
