/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: declare hwi operation defined in platdrv sre_hwi_ipc.c
 * Create: 2019-11-08
 */
#ifndef PLATDRV_SRE_HWI_IPC_H
#define PLATDRV_SRE_HWI_IPC_H

#include <stdint.h>

uint32_t hwi_msg_unregister(uint32_t hwi_num);
void os_hwi_ipc_handler(uint32_t arg);
#endif /* PLATDRV_SRE_HWI_IPC_H */
