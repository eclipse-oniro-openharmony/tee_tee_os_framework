/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */
#ifndef __HI_EFUSE_H__
#define __HI_EFUSE_H__

#define EFUSE_FUSION_MSG

#define EFUSE_MAX_SIZE (128)

#define EFUSE_GRP_AVS (0)
#define EFUSE_AVS_GROUP_SIZE (1)
#define EFUSE_AVS_GROUP_START (0)

/* Efuse Layout */
#define EFUSE_LAYOUT_MP_FLAG_OFFSET (10)
#define EFUSE_LAYOUT_MP_FLAG_LCS_BIT_OFFSET (16)
#define EFUSE_LAYOUT_MP_FLAG_RMA_BIT_OFFSET (31)

#define EFUSE_LAYOUT_KCE_OFFSET (12)
#define EFUSE_LAYOUT_KCE_LENGTH (4)
#define EFUSE_LAYOUT_SECKCE_LENGTH (12)

#define EFUSE_LAYOUT_DFT_AUTH_KEY_OFFSET (59)
#define EFUSE_LAYOUT_DFT_AUTH_KEY_LENGTH (2)

#define EFUSE_LAYOUT_NS_VERIFY_BIT_OFFSET (1184)
#define EFUSE_LAYOUT_CORESIGHT_RST_CTRL_BIT_OFFSET (1987)
#define EFUSE_LAYOUT_HIFI_DBG_CTRL_BIT_OFFSET (1988)
#define EFUSE_LAYOUT_CS_DEVICE_CTRL_BIT_OFFSET (1990)
#define EFUSE_LAYOUT_UART_DBG_CTRL_BIT_OFFSET (1991)
#define EFUSE_LAYOUT_PDE_DBG_CTRL_BIT_OFFSET (1993)
#define EFUSE_LAYOUT_TXP_NIDEN_CTRL_BIT_OFFSET (1994)
#define EFUSE_LAYOUT_ACPU_NIDEN_CTRL_BIT_OFFSET (1995)
#define EFUSE_LAYOUT_SEC_DBG_RST_CTRL_BIT_OFFSET (2004)
#define EFUSE_LAYOUT_DFT_DISABLE_SEL_BIT_OFFSET (2018)

#define EFUSE_LAYOUT_BOOT_SEL_BIT_OFFSET (2020)
#define EFUSE_LAYOUT_APB_RD_HUK_DIS_BIT_OFFSET (2022)
#define EFUSE_LAYOUT_APB_RD_SCP_DIS_BIT_OFFSET (2023)
#define EFUSE_LAYOUT_DFT_AUTH_KEY_RD_CTRL_BIT_OFFSET (2024)

#define EFUSE_LAYOUT_ARM_DBG_CTRL_BIT_OFFSET (2025)
#define EFUSE_LAYOUT_ARM_DBG_CTRL_DBGEN_BIT_OFFSET (2027)
#define EFUSE_LAYOUT_ARM_DBG_CTRL_NIDEN_BIT_OFFSET (2028)
#define EFUSE_LAYOUT_ARM_DBG_CTRL_SPIDEN_BIT_OFFSET (2029)
#define EFUSE_LAYOUT_ARM_DBG_CTRL_SPNIDEN_BIT_OFFSET (2030)
#define EFUSE_LAYOUT_JTAGEN_CTRL_BIT_OFFSET (2047)

#define EFUSE_GRP_DIEID (64)
#define EFUSE_DIEID_SIZE (5)
#define EFUSE_DIEID_BIT (32)
#define EFUSE_DIEID_LEN (EFUSE_DIEID_SIZE * EFUSE_GROUP_SIZE)

#define EFUSE_GRP_HUK (40)
#define EFUSE_HUK_SIZE (4)
#define EFUSE_HUK_LEN (EFUSE_HUK_SIZE * EFUSE_GROUP_SIZE)


#define HI_APB_CLK_FREQ (133 * 1000000)
#define EFUSE_COUNT_CFG (12)
#define PGM_COUNT_CFG (5 * HI_APB_CLK_FREQ / 1000000 - (EFUSE_COUNT_CFG << 2))


/* *********************************************************** */
/*    efuse 寄存器偏移定义（项目名_模块名_寄存器名_OFFSET)        */
/* *********************************************************** */
#define HI_EFUSEC_CFG_OFFSET \
    (0x0) // 配置寄存器，用于使能读/烧写流程，当读完成时，逻辑自动将RDn清除为0。当烧写完成时，逻辑自动将PGEn清除为0
#define HI_EFUSEC_STATUS_OFFSET (0x4) /* 状态寄存器，用于表述读/烧写状态 */
#define HI_EFUSE_GROUP_OFFSET \
    (0x8) /* 读取/烧写地址寄存器。将eufse分组，每组为32bit，对efuse进行烧写或者读取的时候，以一个group为单位 */
#define HI_PG_VALUE_OFFSET (0xC) /* 每次的烧写值寄存器 */
#define HI_EFUSEC_COUNT_OFFSET \
    (0x10) /* efuse内部状态跳转计数器值寄存器。同时该值乘以4作为efuse读操作期间strobe信号脉冲宽度计数值 */
#define HI_PGM_COUNT_OFFSET (0x14)   /* 一次烧写期间strobe信号拉高时间计数器 */
#define HI_EFUSEC_DATA_OFFSET (0x18) /* 存放软件从efuse读取的数据寄存器 */
#define HI_HW_CFG_OFFSET \
    (0x1C) /* 存放efuse上电解复位后从group==127读取的数据寄存器，用于启动判断等。初始值由用户通过efuse烧写确定 */

#define HI_EFUSE_PGEN_BIT 0 /* [0..0] 烧写使能信号，当一次烧写完成后，逻辑将此为自动清零。0：不使能1：使能 */
#define HI_EFUSE_PRE_PG_BIT 1 /* [1..1] 预烧写使能信号，使能后硬件拉低PGENB信号。0：不使能1：使能 */
#define HI_EFUSE_RD_EN_BIT 2 /* [2..2] 读使能信号，当一次读完成后，逻辑将此为自动清零。0：不使能1：使能 */
#define HI_EFUSE_AIB_SEL_BIT 3 /* [3..3] AIB接口选择信号。0：选择AIB操作efuse控制器1：选择APB操作efuse控制器 */

#define HI_EFUSE_PG_STAT_BIT 0    /* [0..0] 烧写状态。0：未完成1：完成 */
#define HI_EFUSE_RD_STAT_BIT 1    /* [1..1] efuse读状态0：未完成1：完成一次读操作 */
#define HI_EFUSE_PGENB_STAT_BIT 2 /* [2..2] 预烧写置位完成状态。0：未完成1：完成预烧写置位状态 */
#define HI_EFUSE_PD_STAT_BIT 4    /* [4..4] power-down状态。0：正常状态1：power-down状态 */
#define HI_EFUSE_PD_EN_BIT 5      /* [5..5] efuse power-down控制。0：不使能1：使能 */

#define HI_EFUSE_GROUP_LBIT 0 /* [6..0] 读取/烧写地址group */
#define HI_EFUSE_GROUP_HBIT 6 /* [6..0] 读取/烧写地址group */

#define HI_EFUSE_PG_VALUE_LBIT 0  /* [31..0] 一组32bit的烧写信息0：不烧写该bit；1：烧写该bit； */
#define HI_EFUSE_PG_VALUE_HBIT 31 /* [31..0] 一组32bit的烧写信息0：不烧写该bit；1：烧写该bit； */

#define HI_EFUSE_DATA_LBIT 0  /* [31..0] 读取group数据 */
#define HI_EFUSE_DATA_HBIT 31 /* [31..0] 读取group数据 */

#define HI_EFUSE_COUNT_LBIT 0 /* [7..0] EFUSE内部状态跳转使用的计数值。 */
#define HI_EFUSE_COUNT_HBIT 7 /* [7..0] EFUSE内部状态跳转使用的计数值。 */

#define HI_EFUSE_PGM_COUNT_LBIT 0 /* [15..0] 一次烧写期间strobe信号拉高时间计数器（以参考时钟为计数时钟） */
#define HI_EFUSE_PGM_COUNT_HBIT 15 /* [15..0] 一次烧写期间strobe信号拉高时间计数器（以参考时钟为计数时钟） */

#define HI_EFUSE_DISFLAG_BIT 0 /* [0..0] 判断是否允许烧写,为1禁止烧写, */

#define HI_ACORE_EFUSE_BASE_ADDR (0xEDF07000)
#define HI_ACORE_SC_AO_CTRL0 (0xEDF00000 + 0x400)
#define HI_MCORE_SC_AO_CTRL0 (0xCDF00000 + 0x400)
#define HI_EFUSEC_REMAP_BIT (0x6)

#define HI_MCORE_EFUSE_BASE_ADDR (0xCDF07000)
#define HI_EFUSEC_COUNT_VALUE (0x14)

#endif // __HI_EFUSE_H__
