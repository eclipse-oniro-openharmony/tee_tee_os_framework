/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: symbles export for use
 * Create: 2022-01
 */
#include <stdint.h>

#ifdef __aarch64__
const char *g_debug_prefix = "libbase_shared";
#else
const char *g_debug_prefix = "libbase_shared_a32";
#endif
