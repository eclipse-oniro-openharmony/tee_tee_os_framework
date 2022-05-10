/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: This file is temporary for modem, AP-CP Decoupling
 * Create: 2022-04-16
 */
#include <drv_hwi_share.h>
#include <sre_hwi.h>

uint32_t SRE_HwiCreate(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode,
                        HWI_PROC_FUNC handler, uint32_t args)
{
    return sys_hwi_create(hwi_num, hwi_prio, mode, handler, args);
}

uint32_t SRE_HwiResume(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode)
{
    return sys_hwi_resume(hwi_num, hwi_prio, mode);
}

uint32_t SRE_HwiDelete(uint32_t hwi_num)
{
    return sys_hwi_delete(hwi_num);
}

uint32_t SRE_HwiDisable(uint32_t hwi_num)
{
    return sys_hwi_disable(hwi_num);
}

uint32_t SRE_HwiEnable(uint32_t hwi_num)
{
    return sys_hwi_enable(hwi_num);
}