/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, secboot function
 * Create: 2019-11-20
 */
#ifndef SECBOOT_DRV_CALL_H
#define SECBOOT_DRV_CALL_H
#include "sre_typedef.h"
#include "mem_page_ops.h" /* paddr_t */

uint32_t __hisi_secboot_process_soc_addr(uint32_t soc_type, const paddr_t src_addr, uint32_t process_type);
uint32_t __hisi_secboot_copy_soc_data(uint32_t soc_type, uint32_t offset, const paddr_t src_addr, uint32_t len);
uint32_t __hisi_secboot_soc_verification(uint32_t socType, uint32_t vrlAddress, paddr_t imageAddress,
                                         uint32_t lock_state);
uint32_t __hisi_secboot_soc_reset(uint32_t soc_type);
uint32_t __hisi_secboot_soc_set(uint32_t soc_type);
void __hisi_secboot_get_vrl_addr(uint32_t vrl_address);
uint32_t __secboot_get_cuid(uint8_t *cuid, uint32_t len);

int32_t __bsp_modem_call(uint32_t func_cmd, uint32_t arg1, void *arg2, uint32_t arg3);

#endif /* SECBOOT_DRV_CALL_H */