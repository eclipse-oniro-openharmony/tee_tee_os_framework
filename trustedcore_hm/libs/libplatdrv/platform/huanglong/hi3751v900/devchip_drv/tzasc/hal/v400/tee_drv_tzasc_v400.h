/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common define for tzasc
 * Author: Hisilicon
 * Create: 2019-06-17
 */

#ifndef _TEE_DRV_TZASC_V400_H_
#define _TEE_DRV_TZASC_V400_H_

/* TZASC register addr */
#define SEC_CONFIG                       (REG_BASE_TZASC + 0x00)
#define SEC_BYPASS                       (REG_BASE_TZASC + 0x04)
#define SEC_LOCKDOWN_SEL                 (REG_BASE_TZASC + 0x10)
#define SEC_INT_MSK_WMID                 (REG_BASE_TZASC + 0x18)
#define SEC_INT_MSK_WMID_EXT             (REG_BASE_TZASC + 0x330)
#define SEC_INT_MSK_RMID                 (REG_BASE_TZASC + 0x1C)
#define SEC_INT_MSK_RMID_EXT             (REG_BASE_TZASC + 0x334)
#define SEC_INT_EN                       (REG_BASE_TZASC + 0x20)
#define SEC_INT_STATUS                   (REG_BASE_TZASC + 0x24)
#define SEC_INT_CLEAR                    (REG_BASE_TZASC + 0x28)
#define SEC_SHARE_RELEASE_MID            (REG_BASE_TZASC + 0x34)
#define SEC_DDRCA_TEE_RGN_EN             (REG_BASE_TZASC + 0x38)
#define SEC_DDRCA_TEE_RGN_START_ADDR     (REG_BASE_TZASC + 0x3C)
#define SEC_DDRCA_TEE_RGN_END_ADDR       (REG_BASE_TZASC + 0x40)
#define SEC_RSP_MSK_WMID                 (REG_BASE_TZASC + 0x44)
#define SEC_RSP_MSK_RMID                 (REG_BASE_TZASC + 0x48)
#define SEC_RSP_MSK_WMID_EXT             (REG_BASE_TZASC + 0x4C)
#define SEC_RSP_MSK_RMID_EXT             (REG_BASE_TZASC + 0x50)
#define SEC_FAIL_ADDRESS_LOW             (REG_BASE_TZASC + 0x80)
#define SEC_FAIL_STATUS                  (REG_BASE_TZASC + 0x84)
#define SEC_FAIL_ID                      (REG_BASE_TZASC + 0x88)

#define SEC_RGN_MAP(x)                   (REG_BASE_TZASC + 0x100 + 0x10 * (x))
#define SEC_RGN_MAP_EXT(x)               (REG_BASE_TZASC + 0x200 + 0x10 * (x))
#define SEC_RGN_ATTR(x)                  (REG_BASE_TZASC + 0x104 + 0x10 * (x))
#define SEC_RGN_MID_W(x)                 (REG_BASE_TZASC + 0x108 + 0x10 * (x))
#define SEC_RGN_MID_W_EXT(x)             (REG_BASE_TZASC + 0x204 + 0x10 * (x))
#define SEC_RGN_MID_R(x)                 (REG_BASE_TZASC + 0x10C + 0x10 * (x))
#define SEC_RGN_MID_R_EXT(x)             (REG_BASE_TZASC + 0x208 + 0x10 * (x))

#define SEC_SHARE_RGN_EN(x)              (REG_BASE_TZASC + 0x300 + 0x20 * (x))
#define SEC_SHARE_RGN_START(x)           (REG_BASE_TZASC + 0x304 + 0x20 * (x))
#define SEC_SHARE_RGN_END(x)             (REG_BASE_TZASC + 0x308 + 0x20 * (x))

#define SEC_MASTER_TYPE_SHARE            (REG_BASE_TZASC + 0x30C)
#define SEC_MASTER_TYPE_SHARE_EXT        (REG_BASE_TZASC + 0x20C)
#define SEC_MASTER_TYPE_RSV              (REG_BASE_TZASC + 0x310)
#define SEC_MASTER_TYPE_RSV_EXT          (REG_BASE_TZASC + 0x21C)
#define SEC_SHARE_RGN_FAIL_CMD_STATUS    (REG_BASE_TZASC + 0x314)
#define SEC_SHARE_RGN_FAIL_CMD_ADDR      (REG_BASE_TZASC + 0x318)
#define SEC_SHARE_RGN_FAIL_CMD_INFO      (REG_BASE_TZASC + 0x31C)

/* TEE_CTRL register addr */
#define SEC_DDRC_CTRL_REG                (REG_BASE_TEE_CTRL + 0x400)

/* sec region config register */
#define _SEC_NR_RGNS_SHIFT                  0
#define _SEC_NR_RGNS_BITS                   8
#define _SEC_BYPASS_SHIFT                   0
#define _SEC_BYPASS_BITS                    8
#define _SEC_INT_EN_SHIFT                   0
#define _SEC_INT_EN_BITS                    1
#define _SEC_INT_OVERRUN_SHIFT              1
#define _SEC_INT_OVERRUN_BITS               1
#define _SEC_INT_STATUS_SHIFT               0
#define _SEC_INT_STATUS_BITS                1
#define _SEC_FAIL_CMD_ACC_TYPE_SHIFT        20
#define _SEC_FAIL_CMD_ACC_TYPE_BITS         1
#define _SEC_FAIL_CMD_NS_SHIFT              17
#define _SEC_FAIL_CMD_NS_BITS               1
#define _SEC_FAIL_CMD_PRVLG_SHIFT           16
#define _SEC_FAIL_CMD_PRVLG_BITS            1
#define _SEC_FAIL_CMD_ADDR_HIGH_SHIFT       0
#define _SEC_FAIL_CMD_ADDR_HIGH_BITS        8
#define _SEC_FAIL_CMD_MID_SHIFT             24
#define _SEC_FAIL_CMD_MID_BITS              8
#define _SEC_FAIL_CMD_ID_SHIFT              0
#define _SEC_FAIL_CMD_ID_BITS               24
#define _SEC_RGN_BASE_ADDR_SHIFT            0
#define _SEC_RGN_BASE_ADDR_BITS             24
#define _SEC_RGN_SIZE_SHIFT                 0
#define _SEC_RGN_SIZE_BITS                  24
#define _SEC_RGN_EN_SHIFT                   31
#define _SEC_RGN_EN_BITS                    1
#define _SEC_RGN_SP_SHIFT                   16
#define _SEC_RGN_SP_BITS                    16
#define _SEC_RGN_SEC_INV_SHIFT              4
#define _SEC_RGN_SEC_INV_BITS               1
#define _SEC_RGN_MID_EN_SHIFT               8
#define _SEC_RGN_MID_EN_BITS                1
#define _SEC_RGN_MID_INV_SHIFT              9
#define _SEC_RGN_MID_INV_BITS               1

/* share region config register */
#define _SEC_SHARE_RGN_EN_SHIFT                   0
#define _SEC_SHARE_RGN_EN_BITS                    1
#define _SEC_SHARE_RGN_FAIL_CMD_STATUS_SHIFT      0
#define _SEC_SHARE_RGN_FAIL_CMD_STATUS_BITS       1
#define _SEC_SHARE_RGN_FAIL_CMD_ID_SHIFT          0
#define _SEC_SHARE_RGN_FAIL_CMD_ID_BITS           14
#define _SEC_SHARE_RGN_FAIL_CMD_NS_SHIFT          16
#define _SEC_SHARE_RGN_FAIL_CMD_NS_BITS           1
#define _SEC_SHARE_RGN_FAIL_CMD_ACC_TYPE_SHIFT    17
#define _SEC_SHARE_RGN_FAIL_CMD_ACC_TYPE_BITS     1
#define _SEC_SHARE_RGN_FAIL_CMD_MID_SHIFT         20
#define _SEC_SHARE_RGN_FAIL_CMD_MID_BITS          6
#define _SEC_SHARE_RGN_FAIL_CMD_ADDR_HIGH_SHIFT   28
#define _SEC_SHARE_RGN_FAIL_CMD_ADDR_HIGH_BITS    4
#define _SEC_SHARE_RELEASE_MID_SHIFT              0
#define _SEC_SHARE_RELEASE_MID_BITS               6
#define _SEC_SHARE_RELEASE_EN_SHIFT               8
#define _SEC_SHARE_RELEASE_EN_BITS                1
#define _SEC_SHARE_RGN_FAIL_CMD_LOCK_MID_SHIFT    12
#define _SEC_SHARE_RGN_FAIL_CMD_LOCK_MID_BITS     1

/* TZPC config register */
#define _SEC_BOOT_LOCK_SHIFT                      5
#define _SEC_BOOT_LOCK_BITS                       1

/* max region numbers */
#define MAX_SEC_REGIONS      16
#define MAX_SHARE_REGIONS    4

/* NS R/W competence on regions */
#define TZASC_NON_SECURE_WRITE      0x5
#define TZASC_NON_SECURE_READ       (0x5 << 4)
#define TZASC_SECURE_WRITE          (0x5 << 8)
#define TZASC_SECURE_READ           (0x5 << 12)

#define TZASC_SP_NONE               0x0
#define TZASC_SP_NON_SEC            (TZASC_NON_SECURE_WRITE | TZASC_NON_SECURE_READ)
#define TZASC_SP_SEC                (TZASC_SECURE_WRITE | TZASC_SECURE_READ)
#define TZASC_SP_FULL               (TZASC_SP_NON_SEC | TZASC_SP_SEC)

/* lockdown the tzasc register */
#define _SEC_LOCKDOWN_SEL_CFG       0x01FF1F0F

/* TZASC IRQ (sec_int) */
#define SEC_TZASC_ERR_IRQ           (104 + 32)

/* region size and addr should be aligned with 4KB(CS FPGA) or 64KB(ES) */
#ifdef CFG_HI_TEE_FPGA_SUPPORT
#define TZASC_RNG_ALIGN_SHIFT       12
#else
#define TZASC_RNG_ALIGN_SHIFT       16
#endif
#define TZASC_RNG_ALIGN_BLOCK       (1 << TZASC_RNG_ALIGN_SHIFT)
#define MAX_DDR_SIZE                0x1000000000ULL  /* 64G */

/* RSP_MSK_MID */
#define TZASC_RSP_MSK_MID_W         0x0
#define TZASC_RSP_MSK_MID_R         (1ULL << 0)  /* MID_CPU */

/* INT_MSK_MID */
#define TZASC_INT_MSK_MID_W         0x0
#define TZASC_INT_MSK_MID_R         (1ULL << 0)  /* MID_CPU */
#endif /* _TEE_DRV_TZASC_V400_H_ */
