/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hieps smmu.
 * Author : z00452790
 * Create: 2019/08/15
 */

#ifndef MSPE_SMMU_V3_H
#define MSPE_SMMU_V3_H

#include "types.h"

uint32_t hieps_mmu_init(void);
uint32_t hieps_mmu_exit(void);
void hieps_mmu_tbu_bypass(void);
void hieps_smmu_interrupt_init(void);

uint32_t hieps_mmu_sce1_enable(uint32_t read_enable, uint32_t write_enable, uint32_t is_sec);
uint32_t hieps_mmu_sce2_enable(uint32_t read_enable, uint32_t write_enable, uint32_t is_sec);

#endif /* MSPE_SMMU_V3_H */
