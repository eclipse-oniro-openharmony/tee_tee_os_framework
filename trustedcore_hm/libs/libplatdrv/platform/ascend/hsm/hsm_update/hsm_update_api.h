/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: update firmware api head file
* Author: chenyao
* Create: 2020/4/6
*/

#ifndef __FIRMUP_API_H__
#define __FIRMUP_API_H__

#include <hsm_dev_id.h>

#define  UPDATE_SUCCESS                     0x0
#define  UPDATE_INPUT_PARAMS_ERR            0x1
#define  UPDATE_FAILED                      0xFFFFFFFFU
#define  UPDATE_CHIP_ID_MAX                 0x2
#define  HISS_SYNC_DDR                      0xE00000
#define  HISS_SYNC_M_DDR                    0x1100000
#define  HISS_SEC_DDR                       0x2000000
#define  HISS_MAX_DDR                       0x2E00000
#define  UFS_CNT_DDR                        0xC6F4D804U
#define  RECOVERY_CNT_DDR                   0xC6F4D890U
#define  RECOVERY_CLR_MASK                  0xFFFF0000U
#define  IMAGE_MAX_SIZE                     (3*1024*1024)
#define  UPDATE_MAX_SIZE                    (8*1024*1024)
#define  FLASH_IMG_MAX_SIZE                 9
#define  UFS_CNT_SIZE                       4
#define  SOC_IMAGE_VERSION_LEN              0x10
#define  SOC_IMAGE_VERSION_OFF              0x2018
#define  HSM_UPDATE_ARGS_LEN                8
#define  SHA256_LEN                         32
#define  ROOT_KEY_LEN                       0x400
#define  EFUSE_NVCNT_LEN_4BYTES             4
#define  EFUSE1_SUBCTRL_BASE                0x80070000U
#define  EFUSE_L2NVCNT_OFFSET               (EFUSE1_SUBCTRL_BASE + 0xE224)

/* flash offset */
#define  HBOOT1_A_M                         0x40000
#define  HILINK_M                           0x50000
#define  HBOOT1_A_B                         0x80000
#define  HILINK_B                           0x90000
#define  HBOOT1_B_M                         0xC0000
#define  HBOOT1_B_B                         0x100000
#define  HBOOT2_M                           0x140000
#define  HBOOT2_B                           0x440000
#define  DDR_IMG_M                          0x740000
#define  DDR_IMG_B                          0x780000
#define  HSM_IMG_M                          0x7C0000
#define  HSM_IMG_B                          0x800000
#define  LP_IMG_M                           0x840000
#define  LP_IMG_B                           0x880000
#define  SI_IMG_M                           0x8C0000
#define  SI_IMG_B                           0x900000
#define  SC_IMG_M                           0x940000
#define  SC_IMG_B                           0x980000
#define  HBOOT2_0_M                         0x140000
#define  HBOOT2_0_B                         0x440000
#define  HBOOT2_1_M                         0x1C0000
#define  HBOOT2_1_B                         0x4C0000
#define  HBOOT2_2_M                         0x240000
#define  HBOOT2_2_B                         0x540000
#define  HBOOT2_3_M                         0x2C0000
#define  HBOOT2_3_B                         0x5C0000
#define  HBOOT2_4_M                         0x340000
#define  HBOOT2_4_B                         0x640000
#define  HBOOT2_5_M                         0x3C0000
#define  HBOOT2_5_B                         0x6C0000

/* flash partition size */
#define HBOOT1_A_SIZE                       0x10000
#define HILINK_SIZE                         0x30000
#define HBOOT1_B_SIZE                       0x40000
#define HBOOT2_SIZE                         0x300000
#define DDR_IMG_SIZE                        0x40000
#define HSM_IMG_SIZE                        0x40000
#define LP_IMG_SIZE                         0x40000
#define SI_IMG_SIZE                         0x40000
#define HBOOT2_S_SIZE                       0x80000
#define SC_IMG_SIZE                         0x40000

/* sram offset */
#define SFC_CHIPOFFSET                      0x8000000000UL
#define SRAM0_CTRL_BASE_ADDR                0xC6F00000U
#define SRAM1_CTRL_BASE_ADDR                (SFC_CHIPOFFSET + SRAM0_CTRL_BASE_ADDR)
#define CMDLINE_OFFSET                      0xC6F4D808U
#define HILINK_SRAM_OFFSET                  0x4DF00
#define HILINK_SRAM_SIZE                    0x22100

/* flash offset(upgrade flag) */
#define  HISS_SEC_UPGRADE_DDR               0xE40000
#define  FLASH_UPGRADE_MAX_SIZE             (128 * 1024)

#define SEC_IMG_BOOT_COUNT_ADDR             0xF068
#define ROOTKEY_OFFSET                      0x58
#define FOUR_BYTE_ALIGN                     0x4
#define HBOOT1_A_ADDR_SIZE                  16
#define HBOOT1_A_LEN_SIZE                   16
#define BIT15                               0x8000
#define DC_FLASH_IMAGE_SIZE                 3
#define MDC_FLASH_IMAGE_SIZE                8
#define FLASH_MASTER                        0
#define FLASH_BAK                           1
#define ARRAY_INDEX0                        0
#define ARRAY_INDEX1                        1
#define ARRAY_INDEX2                        2
#define ARRAY_INDEX3                        3
#define ARRAY_INDEX4                        4
#define ARRAY_INDEX5                        5
#define ARRAY_INDEX6                        6
#define ARRAY_INDEX7                        7
#define HSM_SYNC_DONE                       0x1
#define HSM_SYNC_UNONE                      0x0
#define HSM_FLASH_MAX_SIZE                  (16 * 1024 * 1024)
#define FIRMWARE_IMG_MAX_SIZE               0x300000
#define L3_SRAM_MAX_SIZE                    0x80000
#define SLICE_MAX_SIZE                      0x6
#define NSECURE_IMAGE_PADDR_START           0x31D00000
#define CHIP_ID_MAX_NUMBER                  0x1

#define FLASH_INFO_TYPE_NUM                 15

#define USER_DEFINE_DATA_BYTES                  32
#define HASH_BYTES                              32
#define RSA_ROOTKEY_BYTES                       512
#define IV_BYTES                                16
#define SALT_BYTES                              32
#define TAG_BYTES                               16
#define RSA_SUBKEY_2048_BYTES                   256
#define RSA_SUBKEY_4096_BYTES                   512
#define RVK_SUB_KEY_SIGN_LEN                    512
#define APPEN_SEL_SHIFT                         0x10
#define APPENSEL_MASK                           0x3F
#define SCB_SUBKEY_CERT_OFFSET                  0x500

#define SCB_SIGN_RSA_ALG_MASK                   0x3F
#define SCB_SIGN_RSA_ALG_SHIFT                  16
#define SCB_SIGN_RSA_PKCS_MODE                  0
#define SCB_SIGN_RSA_PSS_MODE                   1

typedef struct {
    uint32_t img_id;
    uint32_t flash_offset;
    uint32_t flash_offset_b;
    uint32_t part_size;
    uint64_t secure_img_vaddr;
    uint32_t img_index;
    uint32_t img_len;
    uint32_t verify_status;
    uint32_t update_status;
    uint8_t bl_hash[SHA256_LEN];
} FLASH_IMAGE_INFO;

typedef enum {
    DSMI_COMPONENT_TYPE_NVE,
    DSMI_COMPONENT_TYPE_XLOADER,
    DSMI_COMPONENT_TYPE_M3FW,
    DSMI_COMPONENT_TYPE_UEFI,
    DSMI_COMPONENT_TYPE_TEE,
    DSMI_COMPONENT_TYPE_KERNEL,
    DSMI_COMPONENT_TYPE_DTB,
    DSMI_COMPONENT_TYPE_ROOTFS,
    DSMI_COMPONENT_TYPE_IMU,
    DSMI_COMPONENT_TYPE_IMP,
    DSMI_COMPONENT_TYPE_AICPU,
    DSMI_COMPONENT_TYPE_HBOOT1_A,
    DSMI_COMPONENT_TYPE_HBOOT1_B,
    DSMI_COMPONENT_TYPE_HBOOT2,
    DSMI_COMPONENT_TYPE_DDR,
    DSMI_COMPONENT_TYPE_LP,
    DSMI_COMPONENT_TYPE_HSM,
    DSMI_COMPONENT_TYPE_SAFETY_ISLAND,
    DSMI_COMPONENT_TYPE_HILINK,
    DSMI_UFS_AREA_TYPE_RAWData,
    DSMI_UFS_AREA_TYPE_RO_SysDrv,
    DSMI_UFS_AREA_TYPE_RO_ADSApp,
    DSMI_UFS_AREA_TYPE_RO_ComIsolator,
    DSMI_UFS_AREA_TYPE_RO_Cluster,
    DSMI_UFS_AREA_TYPE_RO_Customized,
    DSMI_COMPONENT_TYPE_SYS_BASE_CONFIG,
    DSMI_COMPONENT_TYPE_MAX,
    SLICE_HBOOT2_0,
    SLICE_HBOOT2_1,
    SLICE_HBOOT2_2,
    SLICE_HBOOT2_3,
    SLICE_HBOOT2_4,
    SLICE_HBOOT2_5,
    UPGRADE_ALL_UFS_COMPONENT = 0xFFFFFFFD,
    UPGRADE_ALL_FLASH_COMPONENT = 0xFFFFFFFE,
    UPGRADE_ALL_COMPONENT = 0xFFFFFFFF
} DSMI_COMPONENT_TYPE;

typedef struct {
    uint64_t buf_m_va;
    uint64_t buf_b_va;
    uint64_t buf_va;
    uint32_t flash_offset_m;
    uint32_t flash_offset_b;
    uint32_t length;
    uint8_t hash_m[SHA256_LEN];
    uint8_t hash_b[SHA256_LEN];
    uint8_t hash_d[SHA256_LEN];
    uint8_t *hash_bl;
} IMG_PART_DS;

typedef struct secboot_image_head_st {
    uint32_t preamble; /* it will change to jump instruction. so we don't check */
    uint32_t head_len; /* don't check in secure boot */
    uint32_t user_len; /* don't check in secure boot */
    uint8_t  user_define_data[USER_DEFINE_DATA_BYTES]; /* don't check in secure boot */
    uint8_t  code_hash[HASH_BYTES]; /* image hash value, don't check in secure boot */
    uint32_t subkey_cert_offset;
    uint32_t code_sign_algo; /* [15:0] Hash algorithm: 0x0: SHA256, others: reserved
                                [31:22](10 bit)salt len for RSA PSS
                                [21:16](6 bit)sign alg 0x0: RSA_PKCS1, 0x1: RSA_PSS */
    uint32_t root_pubkey_len; /* rootpukkey length, fix to 512 bytes */
    uint8_t  root_pubkey[RSA_ROOTKEY_BYTES]; /* N value */
    uint8_t  root_pubkey_e[RSA_ROOTKEY_BYTES]; /* E value and fixed to 65537 */
    uint32_t code_offset; /* code offset from image head */
    uint32_t code_len;
    uint32_t sign_offset;
    uint32_t code_encrypt_flag;
    uint32_t code_encrypt_algo;
    uint8_t  code_encrypt_iv[IV_BYTES];
    uint8_t  code_derive_salt[SALT_BYTES];
    uint8_t  code_encrypt_tag[TAG_BYTES];
    uint32_t h2c_enable; /* 0x41544941 means enable H2C, otherwise H2C is disabled */
    uint32_t h2c_cert_len;
    uint32_t h2c_cert_offset;
    uint32_t head_magic; /* 0x33cc33cc */
    uint8_t  head_hash[HASH_BYTES];
} SE_IMAGE_HEAD;

typedef union {
    struct {
        uint8_t subkey_n[RSA_SUBKEY_2048_BYTES]; /* subkey module value */
        uint8_t subkey_e[RSA_SUBKEY_2048_BYTES]; /* subkye E value */
        uint8_t subkey_sign[RSA_ROOTKEY_BYTES]; /* signture result */
        uint8_t reserved[RSA_SUBKEY_4096_BYTES]; /* Reserved */
    } subkey_2048;
    struct {
        uint8_t subkey_n[RSA_SUBKEY_4096_BYTES]; /* subkey module value */
        uint8_t subkey_e[RSA_SUBKEY_4096_BYTES]; /* subkye E value */
        uint8_t subkey_sign[RSA_ROOTKEY_BYTES]; /* signture result */
    } subkey_4096;
} SUBKEY;

/* subpubkey cert's data_struct */
typedef struct subkey_cert_st {
    uint32_t subkey_version;
    uint32_t subkey_sign_alg; /* [15:0] stands for Hash algorithm; 0x0:SHA256 others: reserved,
                              [31:22](10bit)signature params.RSA_PKCS1-0
                              [21:16](6bit)signature algorithm. */
    uint32_t subkey_category; /* subkey type */
    uint32_t subkey_id; /* don's used */
    uint32_t subkey_len;
    uint32_t subkey_sign_len; /* signature result's length.RSA4096-512 byte */
    SUBKEY subkey;
} SUB_KEY_CERT;

uint32_t secure_flash_read(uint32_t chip_id, uint32_t flash_offset, uint8_t *buffer, uint32_t length);
uint32_t secure_flash_write(uint32_t chip_id, uint32_t flash_offset, uint8_t *buffer, uint32_t length);
uint32_t secure_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id);
uint32_t secure_img_verify(uint32_t chip_id, uint32_t img_id,
    uint64_t nonsecure_addr, uint32_t length, uint64_t img_addr, uint32_t pss_cfg);
uint32_t secure_update_finish(uint32_t chip_id);
uint32_t secure_sram_read(uint32_t chip_id, uint32_t offset, uint8_t *buf, uint32_t length);
uint32_t secure_upgrade_flash_read(uint32_t chip_id, uint32_t flash_offset, uint8_t *buffer, uint32_t length);
uint32_t secure_upgrade_flash_write(uint32_t chip_id, uint32_t flash_offset, uint8_t *buffer, uint32_t length);
uint32_t secure_sysctrl_read(uint32_t chip_id, uint32_t offset, uint32_t *val);
uint32_t secure_sysctrl_write(uint32_t chip_id, uint32_t offset, uint32_t *val);
uint32_t secure_cmdline_get(uint32_t chip_id, uint32_t *buff, uint32_t size);
uint32_t secure_img_version_get(uint32_t chip_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check);
uint32_t secure_get_dev_num(uint32_t *dev_num);

#endif
