/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: efuse info file
* Author: huawei
* Create: 2019/09/18
*/
#ifndef EFUSE_H
#define EFUSE_H

#include <stdint.h>

#define EFUSE_BLOCK_NUM0_ID             0x0
#define EFUSE_BLOCK_NUM1_ID             0x1

#define WORD_BITS                       32
#define EFUSE_CHECK_SUCCESS             0x1
#define MASK_DEFAULT_VALUE              0xFFFFFFFFU

#define SYSCTRL_REG_BASE                0x80000000U
#define EFUSE_CHIP_OFFSET               0x8000000000U
#define DJTAG_MASTER_EN                 (SYSCTRL_REG_BASE + 0xD800) /* DJTAG master enable reg */
#define DJTAG_MASTER_CFG                (SYSCTRL_REG_BASE + 0xD818) /* DJTAG master config reg */
#define DJTAG_MASTER_ADDR               (SYSCTRL_REG_BASE + 0xD810) /* DJTAG master access addr config reg */
#define DJTAG_MASTER_DATA               (SYSCTRL_REG_BASE + 0xD814) /* DJTAG master access addr write reg */
#define DJTAG_MASTER_START_EN           (SYSCTRL_REG_BASE + 0xD81C) /* DJTAG master start enable reg */
#define DJTAG_RD_DATA0_REG              (SYSCTRL_REG_BASE + 0xE800) /* DJTAG read data reg */
#define BISR_RESET_REQ_REG              (SYSCTRL_REG_BASE + 0xE90) /* BISR RESET reg */
#define BISR_RESET_DREQ_REG             (SYSCTRL_REG_BASE + 0xE94) /* BISR DRESET reg */
#define BISR_RESET_ST_REG               (SYSCTRL_REG_BASE + 0x5E90) /* BISR DRESET reg */

#define EFUSE0_CTRL_BASE                0x81260000
#define SC_PAD_INFO                     (SYSCTRL_REG_BASE + 0xE08C)
#define EFUSE_NS_FORBID                 (EFUSE0_CTRL_BASE + 0xE080)
#define EFUSE1_CTRL_BASE                0x81270000
#define EFUSE_L2NVCNT                   (EFUSE1_CTRL_BASE + 0xE224)

/* EFUSE read & write chain choose */
#define EFUSE_BLOCK_NUM0_CHAIN_W        0x2078ffff
#define EFUSE_BLOCK_NUM0_CHAIN_R        0x78ffff
#define EFUSE_BLOCK_NUM1_CHAIN_W        0x2079ffff
#define EFUSE_BLOCK_NUM1_CHAIN_R        0x79ffff

#define EFUSE_DELAY_COUNT               1000
#define EFUSE_OFFSET_ALIGN              4
#define EFUSE_READ_DATA_TIME            0xFFFFFFF
#define EFUSE_REG_CTRL_OFFSET_BASE      0xC000
#define EFUSE_BUFDATA_OFFSET_BASE       0x8000
#define EFUSE_REG_0X7                   0x7
#define EFUSE_REG_0X8                   0x8
#define EFUSE_REG_VALUE0                0x840
#define EFUSE_REG_VALUE1                0x846
#define EFUSE_UDELAY_COUNT              10000
#define BIT_SIZE                        0x8
#define BISR_RESET_DELAY_5S             0x5
#define CHIP_ID_MAX                     0x1

typedef struct Efuse_Common_Info {
    uint32_t efuse_block_num;
    uint32_t start_bit;
    uint32_t dest_size;
} EFUSE_COMM_INFO;

typedef struct Efuse_Operate_Info {
    uint8_t efuse_block_num;
    uint32_t word;
    uint32_t count;
} EFUSE_OPERATE_INFO;

extern uint32_t get_efuse_base_addr(uint32_t dev_id, uint64_t *base_addr);

#endif
