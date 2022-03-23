/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: symbles export for use
 * Create: 2020-03-20
 */
#include <stdbool.h>
#include "internal.h"

/*
 * DO NOT CHANGE THE NAME OF _cfi_disabled VARIABLE
 * THE SYMBOL OF THIS VARIABLE HAS ALREADY BEEN EXPORTED TO RELEASE VERSION SDK
 * RENAMING WOULD DEFINITELY LEAD TO A "SYMBOL NOT FOUND" ERROR
 */
const unsigned int g_cfi_disabled = 1;

#ifdef CONFIG_GCOV
void __aeabi_unwind_cpp_pr0(void)
{
}
#endif

void hm_yield()
{
    hmapi_yield();
}

void __dump_backtraces()
{
}

int __bsp_efuse_read()
{
    return -1;
}

int __driver_dep_test()
{
    return 0;
}

bool tee_get_usermode()
{
#ifdef DEF_BUILDUSERMODE
    return true;
#else
    return false;
#endif
}

unsigned int g_dx_content_path_addr()
{
    return 0;
}

unsigned int __SRE_HwiMsgCreateEnable()
{
    return -1U;
}

unsigned int get_value()
{
    return 0;
}

bool is_support_tui(void)
{
#if (defined TEE_SUPPORT_TUI_64BIT || defined TEE_SUPPORT_TUI_32BIT)
    return true;
#else
    return false;
#endif
}

#ifdef __aarch64__
const char *g_debug_prefix = "libtee_shared";
#else
const char *g_debug_prefix = "libtee_shared_a32";
#endif
