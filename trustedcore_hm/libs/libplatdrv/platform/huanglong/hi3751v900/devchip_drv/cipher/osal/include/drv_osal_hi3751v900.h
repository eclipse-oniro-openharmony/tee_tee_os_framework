/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: drivers of drv_osal_init
 * Author: cipher team
 * Create: 2019-06-18
 */
#ifndef _DRV_OSAL_HI3751V900_H_
#define _DRV_OSAL_HI3751V900_H_

/* the total cipher hard channel which we can used */
#define CIPHER_HARD_CHANNEL_CNT 0x0F

/* mask which cipher channel we can used, bit0 means channel 0 */
#define CIPHER_HARD_CHANNEL_MASK        0xFFFE

/* the total hash hard channel which we can used */
#define HASH_HARD_CHANNEL_CNT 0x01

/* mask which cipher channel we can used, bit0 means channel 0 */
#define HASH_HARD_CHANNEL_MASK 0x08
#define HASH_HARD_CHANNEL      0x03

/* the total cipher hard key channel which we can used */
#define CIPHER_HARD_KEY_CHANNEL_CNT 0x06

/* mask which cipher hard key channel we can used, bit0 means channel 0 */
#define CIPHER_HARD_KEY_CHANNEL_MASK 0xFC

/* support smmu */
#ifdef CFG_HI_TEE_SMMU_SUPPORT
#define CRYPTO_SMMU_SUPPORT
#endif

#define CRYPTO_OS_INT_SUPPORT

/* the hardware version */
#define CHIP_SYMC_VER_V300
// #define CHIP_HDCP_VER_V300
#define CHIP_HASH_VER_V300
#define CHIP_TRNG_VER_V200
// #define CHIP_IFEP_RSA_VER_V100
#ifndef CFG_HI_TEE_FPGA_SUPPORT
#define CHIP_PKE_VER_V200
#endif
/* #define SOFT_SM3_SUPPORT */
/* #define SOFT_SHA1_SUPPORT */
/* #define SOFT_SHA256_SUPPORT */
/* #define SOFT_SHA512_SUPPORT */
/* #define SOFT_AES_SUPPORT */
/* #define SOFT_PKE_SUPPORT */
/* #define SOFT_ECC_SUPPORT */
#define SOFT_AES_CTS_SUPPORT

/* supoort odd key */
#define CHIP_SYMC_ODD_KEY_SUPPORT

/* supoort SM3 */
#define CHIP_SYMC_SM3_SUPPORT

/* supoort SM4 */
#define CHIP_SYMC_SM4_SUPPORT

/* the hardware capacity */
#define CHIP_AES_CCM_GCM_SUPPORT

/* moudle unsupport, we need set the table */
#define BASE_TABLE_NULL    {\
    .reset_valid = 0,  \
    .clk_valid = 0, \
    .phy_valid = 0, \
    .crg_valid = 0, \
    .ver_valid = 0, \
    .int_valid = 0, \
}

/* define initial value of struct sys_arch_boot_dts for cipher */
#define HARD_INFO_CIPHER {\
    .name = "int_spacc_tee",  \
    .reset_valid = 0,  \
    .clk_valid = 0, \
    .phy_valid = 1, \
    .crg_valid = 1, \
    .ver_valid = 1, \
    .int_valid = 1, \
    .int_num = 172, \
    .version_reg = 0x308, \
    .version_val = 0x0, \
    .reg_addr_phy = 0xb0bc0000, \
    .reg_addr_size = 0x10000,    \
    .crg_addr_phy = 0xb60104, \
    .reset_bit = 4, \
    .clk_bit = 5, \
}

/* define initial value of struct sys_arch_boot_dts for cipher */
#define HARD_INFO_HASH {\
    .name = "int_spacc_tee",  \
    .reset_valid = 0,  \
    .clk_valid = 0, \
    .phy_valid = 1, \
    .crg_valid = 0, \
    .ver_valid = 0, \
    .int_valid = 1, \
    .int_num = 172, \
    .reg_addr_phy = 0xb0bc0000, \
    .reg_addr_size = 0x10000, \
}

/* define initial value of struct sys_arch_boot_dts for HASH */
#define HARD_INFO_TRNG {\
    .name = "trng",  \
    .reset_valid = 0,  \
    .clk_valid = 0, \
    .phy_valid = 1, \
    .crg_valid = 0, \
    .ver_valid = 0, \
    .int_valid = 0, \
    .reg_addr_phy = 0xB0B0C200,  \
    .reg_addr_size = 0x100,   \
}

/* define initial value of struct sys_arch_boot_dts for SM2 */
#define HARD_INFO_PKE {\
    .name = "int_pke_tee",  \
    .reset_valid = 1,  \
    .clk_valid = 1, \
    .phy_valid = 1, \
    .crg_valid = 1, \
    .ver_valid = 0, \
    .int_valid = 1, \
    .reg_addr_phy = 0xb0B90000,  \
    .reg_addr_size = 0x2000,\
    .crg_addr_phy = 0xb0B60104, \
    .reset_bit = 2, \
    .clk_bit = 3, \
    .int_num = 168, \
    .version_reg = 0x88, \
    .version_val = 0x00000009, \
}

#define HARD_INFO_SMMU             BASE_TABLE_NULL
#define HARD_INFO_SIC_RSA          BASE_TABLE_NULL
#define HARD_INFO_CIPHER_KEY       BASE_TABLE_NULL
#define HARD_INFO_SM4              BASE_TABLE_NULL
#define HARD_INFO_IFEP_RSA         BASE_TABLE_NULL
#endif
