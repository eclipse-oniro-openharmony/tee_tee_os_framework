/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader timer read function
 * Create: 2020-12
 */
#include <arch-arm/timer.h>


unsigned long arch_timer_read(void)
{
#define ID_PFR1_GENERIC_TIMER_MASK    0x000f0000
#define ID_PFR0_PERF_MONITORS_MASK    0x0f000000
    unsigned long val = 0;
    unsigned long id_pfr1 = 0;
    unsigned long id_dfr0 = 0;

    /* Read ID_PFR1 Reg into id_pfr1 */
    asm volatile(
    "    mrc    p15, 0, %0, c0, c1, 1\n"
        : "=r" (id_pfr1));
    if (id_pfr1 & ID_PFR1_GENERIC_TIMER_MASK) {
        /* Read CNTVCT Reg into val
         * The CNTVCT holds the virtual count, what is obtained by
         * subtracting the virtual offset from the physical count
         */
        asm volatile(
        "    mrrc    p15, 1, %0, r2, c14\n"
            : "=r" (val) : : "r2");
        return val;
    }

    /* Read ID_DFR0 Reg into id_dfr0 */
    asm volatile(
    "    mrc    p15, 0, %0, c0, c1, 2\n"
        : "=r" (id_dfr0));
    if ((id_dfr0 & ID_PFR0_PERF_MONITORS_MASK) !=
        ID_PFR0_PERF_MONITORS_MASK) {
        /* Read PMCCNTR Reg into val
         * The PMCCNTR holds the value of the processor Cycle Counter,
         * CCNT, that counts processor clock cycles.
         */
        asm volatile(
        "    mrc    p15, 0, %0, c9, c13, 0\n"
            : "=r" (val));
        return val;
    }
    return 1;
#undef ID_PFR0_PERF_MONITORS_MASK
#undef ID_PFR1_GENERIC_TIMER_MASK
}
