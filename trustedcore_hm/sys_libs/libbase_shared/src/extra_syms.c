/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: symbles export for use
 * Create: 2022-01
 */
#include <stdint.h>

/*
 * DO NOT CHANGE THE NAME OF _cfi_disabled VARIABLE
 * THE SYMBOL OF THIS VARIABLE HAS ALREADY BEEN EXPORTED TO RELEASE VERSION SDK
 * RENAMING WOULD DEFINITELY LEAD TO A "SYMBOL NOT FOUND" ERROR
 */
const unsigned int g_cfi_disabled = 1;

#ifdef __aarch64__
const char *g_debug_prefix = "libbase_shared";
#else
const char *g_debug_prefix = "libbase_shared_a32";
#endif
