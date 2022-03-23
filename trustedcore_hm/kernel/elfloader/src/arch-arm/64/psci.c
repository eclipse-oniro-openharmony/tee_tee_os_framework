/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cpu on in psci style
 * Create: 2020-12
 */
#include <autoconf.h>
#include <log.h>

#define SMC64_FID_VER         0x84000000
#define SMC64_FID_CPU_SUSPEND 0xc4000001
#define SMC64_FID_CPU_OFF     0x84000002
#define SMC64_FID_CPU_ON      0xc4000003

extern int psci_func(unsigned int id, unsigned long param1, unsigned long param2, unsigned long param3);

int psci_cpu_on(unsigned long target_cpu, unsigned long entry_point, unsigned long context_id)
{
    int ret = psci_func(SMC64_FID_CPU_ON, target_cpu, entry_point, context_id);
    return ret;
}
