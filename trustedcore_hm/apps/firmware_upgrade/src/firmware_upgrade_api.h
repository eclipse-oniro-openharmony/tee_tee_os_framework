/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: hsm firmware safety upgrade head file
 * Author: chenyao
 * Create: 2019-03-01
 */
#ifndef FIRMWARE_UPGRADE_API_H
#define FIRMWARE_UPGRADE_API_H

#include "tee_ext_api.h"

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

#define NVE_OFFSET                      0x940000
#define NVCNT_PAD_NUMBER                0x3
#define NVCNT_UFS_NUMBER                16

#define FIRM_UPGRADE_FLASH_ADDR         0xE40000
#define FIRM_UPGRADE_BAK_FLASH_ADDR     0xE50000

#define FIRM_UPGRADE_SHIFT_32           32

#define SRAM_CTRL_BOOT_ADDR             0x4D808
#define SRAM_CTRL_RESET_CNT_ADDR        0xF068
#define SRAM_IMG_NVCNT_OFFSET           0x4D800

#define TEE_HSM_MASTER_CNT              0x0
#define TEE_HSM_BAK_CNT                 0x4
#define TEE_HSM_MAX_CNT                 0x8
#define TEE_HSM_MASTER_UPGRADE          0xC11CB55BU
#define TEE_HSM_UPGRADE_DONE            0xD6C55BC1U
#define TEE_HSM_SYNC_DONE               0x1

#define BIT15                           0x8000
#define SC_PAD_INFO_OFFSET              0xE08C
#define DC_FLASH_IMAGE_SIZE             3
#define TEE_HSM_RIM_LEN                 544
#define TEE_HSM_ROOTKEY_LEN             1024
#define TEE_HSM_RIM_INFO_LEN            1568
#define IMG_NVCNT_MAGIC                 0xA7E358FDU
#define IMG_NVCNT_END_MAGIC             0xA6F8D762U

#define HBOOT2_SIZE                     0x300000
#define HBOOT2_S_SIZE                   0x80000

#define ROOT_UID                        0
#define HWHIAIUSER_UID                  1000
#define SYSCTRL_UPGRADE_FLAG_OFFSET     0xF074
#define SYSCTRL_UPGRADE_FLAG_MASK       0xFFFFF0FFU
#define SYSCTRL_UPGRADE_FLAG_VAL        0x500
#define EFUSE_NVCNT_LEN_4BYTES          4

#define FIRMWARE_UPGRADE_CA             "hsm-ca-update-firmware"
#define OPEN_SESSION_PARA_NUM           4
#define UFS_NVCNT_0                     0x0
#define UFS_NVCNT_1                     0x1
#define UFS_NVCNT_2                     0x2
#define UFS_NVCNT_3                     0x3
#define UFS_NVCNT_4                     0x4

#define DEV_NUM_MAX                     2
#define FLASH_INFO_TYPE_NUM             14

#define HISS_SUBCTRL_BASE_ADDR                  0x10100000
#define HSC_FORBID_CODE_ST                      (HISS_SUBCTRL_BASE_ADDR + 0x6040)
#define SCB_EFUSE_FEATURE_DISABLE               0x1a4a5252
#define RVK_SUB_KEY_SIGN_LEN                    512
#define SCB_SIGN_RSA_PSS_MODE                   1
#define APPEN_SEL_SHIFT                         0x10
#define APPENSEL_MASK                           0x3F

enum HSM_SEC_IMG_CMD {
    HSM_SEC_IMG_VERIFY_CMD              = 0x7000,
    HSM_SEC_IMG_UPDATE_CMD              = 0x7001,
    HSM_SEC_IMG_UPDATE_FINISH_CMD       = 0x7003,
    HSM_SEC_IMG_SYNC_AND_EFUSE_UPDATE   = 0x7004,
    HSM_SEC_RIM_UPDATE                  = 0x7005,
    HSM_SEC_VERSION_GET                 = 0x700A,
    HSM_SEC_COUNT_GET                   = 0x700B,
    HSM_SEC_INFO_GET                    = 0x700C,
    HSM_SEC_UFS_CNT_READ                = 0x7100,
    HSM_SEC_UFS_CNT_WRITE               = 0x7101,
    HSM_SEC_CLEAR_CNT                   = 0x7102,
    HSM_SEC_SYNC_BEFORE_UPGRADE         = 0x7103,
    HSM_SEC_FLASH_GET_CMDLINED          = 0x7104,
    SOC_GET_EFUSE_NVCNT                 = 0x7105,
    HSM_SEC_RESET_RECOVERT_BOOT_CNT     = 0x7106,
};

typedef uint32_t (*tee_upgrade_cmd_process)(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);

typedef struct {
    uint32_t cmd;
    tee_upgrade_cmd_process fn;
} tee_upgrade_cmd;

typedef struct {
    uint32_t dev_id;
    uint32_t img_id;
    uint8_t *buf;
    uint32_t buf_len;
    uint32_t end_state;
} SEC_IMG_VERIFY_S;

typedef struct {
    uint32_t done;
    uint32_t part_select;
    uint32_t sync_done;
} UPGRADE_FLAG;

typedef struct {
    uint32_t image : 1;
    uint32_t initrd : 1;
    uint32_t dtb : 1;
    uint32_t tee : 1;
    uint32_t rootfs : 1;
    uint32_t rev1 : 3;
    uint32_t hboot1_a : 1;
    uint32_t hilink : 1;
    uint32_t hboot1_b : 1;
    uint32_t hboot2 : 1;
    uint32_t lpddr : 1;
    uint32_t lp : 1;
    uint32_t hiss : 1;
    uint32_t sil : 1;
    uint32_t syscfg : 1;
    uint32_t rev2 : 15;
} BOOT_FLAG;

typedef struct {
    uint32_t img_id;
    uint32_t part_boot;
} FLASH_PART_INFO;

typedef struct {
    uint32_t nv_cnt_pad[NVCNT_PAD_NUMBER];
    uint32_t magic;
    uint32_t hboot1_a_nvcnt;
    uint32_t hilink_nvcnt;
    uint32_t hboot1_b_nvcnt;
    uint32_t hboot2_nvcnt;
    uint32_t lpddr_nvcnt;
    uint32_t lp_nvcnt;
    uint32_t hiss_nvcnt;
    uint32_t sil_nvcnt;
    uint32_t syscfg_nvcnt;
    uint32_t nv_cnt_ufs[NVCNT_UFS_NUMBER];
} IMG_NVCNT_S;

typedef struct {
    uint32_t            subkey_version;
    uint32_t            plaintext_len;
    uint32_t            sign_alg;
    uint32_t            subkey_category;
    uint32_t            subkey_id;
    uint32_t            sign_len;
    uint32_t            user_define1;
    uint32_t            user_define2;
    uint8_t             sign_result[RVK_SUB_KEY_SIGN_LEN];
} CER_RIM_DATA_LIST;

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
    UPGRADE_ALL_UFS_COMPONENT = 0xFFFFFFFDU,
    UPGRADE_ALL_FLASH_COMPONENT = 0xFFFFFFFEU,
    UPGRADE_ALL_COMPONENT = 0xFFFFFFFFU
} DSMI_COMPONENT_TYPE;

uint32_t sec_img_verify(uint64_t nsecure_addr, uint32_t length, uint32_t dev_id, uint32_t img_id, uint32_t pss_cfg);
uint32_t sec_img_update(uint32_t dev_id, uint32_t img_index);
uint32_t sec_update_finish(uint32_t dev_id);
uint32_t sec_img_sync_entry(uint32_t dev_id);
uint32_t sec_img_sync_and_efuse_update(uint32_t dev_id);
uint32_t sec_rim_update(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_len);
uint32_t sec_img_info_get(uint32_t dev_id, uint32_t flash_index, uint8_t *buffer, uint32_t buffer_size);
uint32_t sec_img_count_get(uint32_t dev_id, uint32_t *count);
uint32_t sec_img_version_get(uint32_t dev_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check);
uint32_t sec_ufs_cnt_read(uint32_t dev_id, uint32_t *out_value);
uint32_t sec_ufs_cnt_write(uint32_t dev_id, uint32_t in_value);
uint32_t sec_img_sync_before_upgrade(uint32_t dev_id);
uint32_t get_cmdline_info(uint32_t dev_id, uint32_t *buf, uint32_t len);
uint32_t sec_cnt_clear(uint32_t dev_id);
uint32_t get_efuse_nvcnt(uint32_t dev_id, uint8_t *buf, uint32_t buf_size);
uint32_t sec_recovery_cnt_reset(uint32_t dev_id);

#endif
