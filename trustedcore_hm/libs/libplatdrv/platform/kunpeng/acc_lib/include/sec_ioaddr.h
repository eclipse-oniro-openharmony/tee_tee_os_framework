/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sec device register address
 * Author: zhanglinhao zhanglinhao@huawei.com
 * Create: 2020-10
 */

#ifndef SEC_IOADDR_H
#define SEC_IOADDR_H

/* PBU */
#define SEC_PBU_REGS_BASE_ADDR                         0xD7408000
#define SEC_PBU_PCIHDR_CMDSTS_REG                      (SEC_PBU_REGS_BASE_ADDR + 0x0004)
#define SEC_PBU_PCIHDR_BUS_NUM_REG                     (SEC_PBU_REGS_BASE_ADDR + 0x0018)
#define SEC_PBU_PCIHDR_MEM_BASE_LIMIT_REG              (SEC_PBU_REGS_BASE_ADDR + 0x0020)
#define SEC_PBU_PCIHDR_PRE_MEM_BASE_LIMIT_REG          (SEC_PBU_REGS_BASE_ADDR + 0x0024)
#define SEC_PBU_PCIHDR_PRE_MEM_BASE_UPADR_REG          (SEC_PBU_REGS_BASE_ADDR + 0x0028)
#define SEC_PBU_PCIHDR_PRE_MEM_LIMIT_UPADR_REG         (SEC_PBU_REGS_BASE_ADDR + 0x002C)


#define PEH_PF_REGS_BASE_ADDR  0xd7600000
#define PCIHDR_CMDSTS_REG            (PEH_PF_REGS_BASE_ADDR + 0x0004)
#define PCIHDR_BAR2_REG              (PEH_PF_REGS_BASE_ADDR + 0x0018)
#define PCIHDR_BAR3_REG              (PEH_PF_REGS_BASE_ADDR + 0x001C)
#endif
