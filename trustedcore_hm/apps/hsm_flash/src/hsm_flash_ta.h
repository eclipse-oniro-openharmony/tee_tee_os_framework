/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: mdc flash read write erase head file
 * Author: huawei
 * Create: 2021-04-16
 */

#ifndef HSM_FLASH_TA_H
#define HSM_FLASH_TA_H

#include <stdint.h>

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

#define ROOT_UID                        0
#define HWHIAIUSER_UID                  1000
#define MAC_MAX_SIZE                    0x10000
#define FLASH_CA_PATH                   "/vendor/bin/teec_hello"
#define HSM_FLASH_CA                    "hsm-ca-flash"
#define ROOT_UID                        0
#define HWHIAIUSER_UID                  1000
/* PN: DTS2021091014493 */
#define FIRMWARE_END_ADDR               0x9C0000
#define UPGRADE_TAG_START_ADDR          0xE40000
#define UPGRADE_MAC_END_ADDR            0xE70000
#define FLASH_LEN_MAX                   (16 * 1024 * 1024)

#define OPEN_SESSION_PARA_NUM           4
#define PARAMS_NUM_0                    0
#define PARAMS_NUM_1                    1
#define PARAMS_NUM_2                    2

#define FLASHBOOT_OFFSET                0x0
#define HBOOT1A_OFFSET                  0x40000
#define HLINK_OFFSET                    0x50000
#define HBOOT1A_BAK_OFFSET              0x80000
#define HLINK_BAK_OFFSET                0x90000
#define HBOOT1B_OFFSET                  0xC0000
#define HBOOT1B_BAK_OFFSET              0x100000
#define HBOOT2_OFFSET                   0x140000
#define HBOOT2_BAK_OFFSET               0x440000
#define DDR_IMG_OFFSET                  0x740000
#define DDR_IMG_BAK_OFFSET              0x780000
#define HSM_IMG_OFFSET                  0x7C0000
#define HSM_IMG_BAK_OFFSET              0x800000
#define IP_IMG_OFFSET                   0x840000
#define IP_IMG_BAK_OFFSET               0x880000
#define SAFETY_IMG_OFFSET               0x8C0000
#define SAFETY_IMG_BAK_OFFSET           0x900000
#define SYSCFG_IMG_OFFSET               0x940000
#define SYSCFG_IMG_BAK_OFFSET           0x980000
#define NVE_OFFSET                      0x9C0000
#define USER_CONFIG_OFFSET              0xA40000
#define IMG_UPGRADE_FLG_OFFSET          0xE40000
#define IMG_UPGRADE_FLG_BAK_OFFSET      0xE50000
#define MAC_ADDR_OFFSET                 0xE60000
#define TEST_AREA_OFFSET                0xE70000
#define RESERVED_AREA_OFFSET            0xEB0000

/* recovery function flash addr */
#define RECOVERY_UPGRADE_SYNC_ADDR      0xE40000
#define RECOVERY_MASTER_SLAVE_ADDR      0xE40004
#define RECOVERY_MODE_SET_ADDR          0xE40010

/* recovery function flash assign value */
#define RECOVERY_UPGRADE_FLAG           0xD6C55BC1U
#define RECOVERY_SYNC_FLAG              0x0
#define RECOVERY_PARTITION_MASTER_FLAG  0xC11CB55BU
#define RECOVERY_PARTITION_SLAVE_FLAG   0x3443DAAD
#define RECOVERY_FORCE_ENTER_FLAG       0x464F5243
#define RECOVERY_UNFORCE_ENTER_FLAG     0x0

enum TEE_MDC_FLASH_CMD {
    TEE_HSM_FLASH_WRITE                 = 0x9000,
    TEE_HSM_FLASH_READ                  = 0x9001,
    TEE_HSM_FLASH_ERASE                 = 0x9002,
    TEE_MDC_FLASH_READ                  = 0x9003,
    TEE_MDC_FLASH_WRITE                 = 0x9004,
    TEE_HSM_RECOVERY_FLAG_SET           = 0x9005,
    TEE_HSM_RECOVERY_FLAG_GET           = 0x9006,
    TEE_HSM_RECOVERY_FLAG_CLR           = 0x9007,
    TEE_HSM_RECOVERY_STATUS_SET         = 0x9008,
};

enum dsmi_recovery_ops_type {
    RECOVERY_UPGRADE = 0,
    RECOVERY_SYNC = 1
};

enum dsmi_recovery_area_type {
    RECOVERY_PARTITION_MASTER = 0,
    RECOVERY_PARTITION_SLAVE = 1
};

enum SEC_FLASH_PARTITION {
    flashboot                         = 0,
    hboot1a                           = 1,
    hlink                             = 2,
    hboot1a_bak                       = 3,
    hlink_bak                         = 4,
    hboot1b                           = 5,
    hboot1b_bak                       = 6,
    hboot2                            = 7,
    hboot2_bak                        = 8,
    ddr_img                           = 9,
    ddr_img_bak                       = 10,
    lp_img                            = 11,
    lp_img_bak                        = 12,
    hsm_img                           = 13,
    hsm_img_bak                       = 14,
    safety_img                        = 15,
    safety_img_bak                    = 16,
    syscfg_img                        = 17,
    syscfg_img_bak                    = 18,
    nve                               = 19,
    user_config                       = 20,
    img_upgrade_flag                  = 21,
    img_upgrade_flag_bak              = 22,
    mac_addr                          = 23,
    test_area                         = 24,
    reserved_area                     = 25,
    max_part_num                      = 26
};

enum flash_op {
    FLASH_OP_READ,
    FLASH_OP_WRITE,
    FLASH_OP_ERASE,
};

typedef struct {
    uint32_t part;
    uint32_t flash_addr;
} SEC_FLASH_ADDRESS_INFO_S;
#endif
