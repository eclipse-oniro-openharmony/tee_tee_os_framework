/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: plat_cfg defines
 * Author: hemuyang1@huawei.com
 * Create: 2022-02-17
 */

#include "plat_cfg_public.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

/*
 * In the independent decoupling solution, the global variable is re-assigned upon startup.
 * Therefore, no valid value is required. However, a non-zero value must be assigned to the global variable.
 * Otherwise, the global variable is stored in the bss section and cleared to 0 upon startup.
 */
struct platform_info g_plat_cfg = {
    .phys_region_start = 0x34000000,
};
