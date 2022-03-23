/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader timer read function
 * Create: 2020-12
 */
#include <arch-arm/timer.h>

unsigned long arch_timer_read(void)
{
#define CNTPS_CTL_ENABLE (1 << 0)
#define CNTPS_CTL_IMASK  (1 << 1)
    unsigned long val = 0;
    /*
     * Perfered use CNTPS_TVAL_EL1 in secure world, but it's determined with SCR_EL3
     * SCR_EL3 ST is set to zero ,Secure EL1 will be trap to EL3
     * with ARM8.4, SEL2 ENALBED CNTPS_TVAL is Upgrade to EL3 USED
     * Now use cntpct_el0 and cntvct_el0 readonly register after system reset
     */
    asm volatile("isb");
    asm volatile("mrs %0, cntpct_el0" : "=r" (val));
    asm volatile("isb");

    if (val != 0) {
        return val;
    } else {
        asm volatile("mrs %0, cntvct_el0" : "=r" (val));
        asm volatile("isb");
    }
    return val;
}
