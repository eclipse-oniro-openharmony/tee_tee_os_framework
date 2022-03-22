/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the header file for driver dynamic lib
 * Create: 2021-04
 */
#ifndef LIBDRV_HWI_SHARED_H
#define LIBDRV_HWI_SHARED_H

#include <stdint.h>
#include <sre_hwi.h>
#include <crypto_driver_adaptor.h>

uint32_t sys_hwi_create(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode,
                        HWI_PROC_FUNC handler, uint32_t args);
uint32_t sys_hwi_resume(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode);
uint32_t sys_hwi_delete(uint32_t hwi_num);
uint32_t sys_hwi_disable(uint32_t hwi_num);
uint32_t sys_hwi_enable(uint32_t hwi_num);
int32_t sys_hwi_notify(uint32_t hwi_num);

#endif
