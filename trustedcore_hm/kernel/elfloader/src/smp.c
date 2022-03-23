/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader smp function file
 * Create: 2020-12
 */
#include <autoconf.h>
#include <types.h>
#include <arch/machine/registerset.h>

#if CONFIG_MAX_NUM_NODES > 1
void init_slave_cpus(void)
{
    /* set the logic id for the booting core */
#ifdef CONFIG_ARCH_AARCH64
    uint64_t v64 = 0;
    MSR("tpidr_el1", v64);
#else
    MCR("p15, 0, %0, c13, c0, 4", 0);
#endif
}
#endif
