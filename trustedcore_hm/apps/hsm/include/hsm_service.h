/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm service header file
* Author: huawei
* Create: 2020/1/8
*/

#ifndef HSM_SERVICE_H
#define HSM_SERVICE_H

#include <stdint.h>
#include <hsm_command.h>

#define DEVICE_NUM                                   2
#define CHIP_PADDR_OFFSET_H                          0x80U

extern uint64_t g_hsm_tee_smem_start_vaddr[DEVICE_NUM];
extern MAIN_KEY_INFO g_main_key[DEVICE_NUM];
extern TA_KEY_INFO g_ta_keys[DEVICE_NUM][TA_MAX_NUM];

#define SCMI_SUCCESS                                 0

#define HSM_TEE_SHARE_DDR_PHY_ADDR                   0x2E00000U
#define HSM_TEE_DDR_BLOCK_SIZE                       3072U
#define HSM_TEE_START_MAIN_KEY_INIT_PADDR            HSM_TEE_SHARE_DDR_PHY_ADDR
#define HSM_TEE_FINISH_MAIN_KEY_INIT_PADDR           (HSM_TEE_START_MAIN_KEY_INIT_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_START_ESTABLISSH_SESSION_PADDR       (HSM_TEE_FINISH_MAIN_KEY_INIT_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_FINISH_ESTABLISH_SESSION_PADDR       (HSM_TEE_START_ESTABLISSH_SESSION_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_PRODUCE_SYMMETRIC_KEY_PADDR          (HSM_TEE_FINISH_ESTABLISH_SESSION_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_PRODUCE_ASYMMETRIC_KEY_PADDR         (HSM_TEE_PRODUCE_SYMMETRIC_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_DERIVE_HUK_PADDR                     (HSM_TEE_PRODUCE_ASYMMETRIC_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_DERIVE_EXTERNAL_KEY_PADDR            (HSM_TEE_DERIVE_HUK_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_IMPORT_IPK1_PADDR                    (HSM_TEE_DERIVE_EXTERNAL_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* key management */
#define HSM_TEE_CIPHER_START_PADDR                   (HSM_TEE_IMPORT_IPK1_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_CIPHER_PROCESS_PADDR                 (HSM_TEE_CIPHER_START_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_CIPHER_FINISH_PADDR                  (HSM_TEE_CIPHER_PROCESS_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_MAC_START_PADDR                      (HSM_TEE_CIPHER_FINISH_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_MAC_PROCESS_PADDR                    (HSM_TEE_MAC_START_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_MAC_FINISH_PADDR                     (HSM_TEE_MAC_PROCESS_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_HASH_START_PADDR                     (HSM_TEE_MAC_FINISH_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_HASH_UPDATE_PADDR                    (HSM_TEE_HASH_START_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_HASH_FINISH_PADDR                    (HSM_TEE_HASH_UPDATE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_SIGN_START_PADDR                     (HSM_TEE_HASH_FINISH_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_SIGN_UPDATE_PADDR                    (HSM_TEE_SIGN_START_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_SIGN_FINISH_PADDR                    (HSM_TEE_SIGN_UPDATE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_VERIFY_START_PADDR                   (HSM_TEE_SIGN_FINISH_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_VERIFY_UPDATE_PADDR                  (HSM_TEE_VERIFY_START_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_VERIFY_FINISH_PADDR                  (HSM_TEE_VERIFY_UPDATE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_GEN_RANDOM_PADDR                     (HSM_TEE_VERIFY_FINISH_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* crypto */
#define HSM_TEE_IMPORT_IPK2_PADDR                    (HSM_TEE_GEN_RANDOM_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_PRODUCE_NEGOTIATION_PKEY_PADDR       (HSM_TEE_IMPORT_IPK2_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_PRODUCE_NEGOTIATION_KEY_PADDR        (HSM_TEE_PRODUCE_NEGOTIATION_PKEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_SH_KEY_PADDR                         (HSM_TEE_PRODUCE_NEGOTIATION_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_UPDATE_GUARDING_KEY_PADDR            (HSM_TEE_SH_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_UPDATE_VERIFY_INFO_PADDR             (HSM_TEE_UPDATE_GUARDING_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_DELETE_CIPHER_PADDR                  (HSM_TEE_UPDATE_VERIFY_INFO_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_EXPORT_IPK1_PADDR                    (HSM_TEE_DELETE_CIPHER_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_EXPORT_IPK2_PADDR                    (HSM_TEE_EXPORT_IPK1_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_GEN_TA_KEY_PADDR                     (HSM_TEE_EXPORT_IPK2_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* bbox */
#define HSM_TEE_BBOX_PADDR                           (HSM_TEE_GEN_TA_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* counter */
#define HSM_COUNTER_INIT_PADDR                       (HSM_TEE_BBOX_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_COUNTER_CREATE_PADDR                     (HSM_COUNTER_INIT_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_COUNTER_READ_PADDR                       (HSM_COUNTER_CREATE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_COUNTER_DELETE_PADDR                     (HSM_COUNTER_READ_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_COUNTER_INC_PADDR                        (HSM_COUNTER_DELETE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* algorithm check */
#define HSM_ALG_CHECK_PADDR                          (HSM_COUNTER_INC_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_GEN_RPMB_KEY_PADDR                       (HSM_ALG_CHECK_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_GEN_RPMB_WRAP_KEY_PADDR                  (HSM_GEN_RPMB_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* soc verify */
#define HSM_SOC_VERIFY_PADDR                         (HSM_GEN_RPMB_WRAP_KEY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* efuse rim and nv_cnt */
#define HSM_RIM_UPDATE_PADDR                         (HSM_SOC_VERIFY_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_EFUSE_PWR_ON_PADDR                       (HSM_RIM_UPDATE_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_EFUSE_PWR_OFF_PADDR                      (HSM_EFUSE_PWR_ON_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_HBOOT1A_TRANS_PADDR                      (HSM_EFUSE_PWR_OFF_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

/* notify hsm prereset */
#define HSM_TEE_NOTIFY_PRERESET_PADDR                (HSM_HBOOT1A_TRANS_PADDR + HSM_TEE_DDR_BLOCK_SIZE)
#define HSM_TEE_FUZZ_SERVICE_PADDR                   (HSM_TEE_NOTIFY_PRERESET_PADDR + HSM_TEE_DDR_BLOCK_SIZE)

#define HSM_PROCESS_SUCCESS                          0x1000000
#define SHIFT_CONST_NUM_32                           32
#define HSM_DDR_PARA_NUM0                            0
#define HSM_DDR_PARA_NUM1                            1
#define HSM_DDR_PARA_NUM2                            2
#define HSM_DDR_PARA_NUM3                            3
#define HSM_DDR_PARA_NUM4                            4
#define HSM_DDR_PARA_NUM5                            5
#define HSM_DDR_PARA_NUM6                            6
#define HSM_DDR_PARA_NUM7                            7
#define HSM_DDR_PARA_NUM8                            8

#define CHANNEL_NUM_0                                0x0

#define TA_LIST_NUMBER                               0x6
#define TA_ID0                                       0x0
#define TA_ID1                                       0x1
#define TA_ID2                                       0x2
#define TA_ID3                                       0x3

#define TEST_INDEX                                   0x0
#define TEST_PART0                                   0x58dbb3b9U
#define TEST_PART1                                   0x42d24a0CU
#define TEST_PART2                                   0x7a7c4da8U
#define TEST_PART3                                   0xfc3975b1U

#define BBOX_INDEX                                   0x1
#define BBOX_PART0                                   0x9d420a21U
#define BBOX_PART1                                   0x473eb440U
#define BBOX_PART2                                   0x93ab54b3U
#define BBOX_PART3                                   0xd1a6e210U

#define RPMB_INDEX                                   0x2
#define RPMB_PART0                                   0x6fd66c9cU
#define RPMB_PART1                                   0x4610017cU
#define RPMB_PART2                                   0x65a6da80U
#define RPMB_PART3                                   0x62069ba7U

#define FIRMUP_INDEX                                 0x3
#define FIRMUP_PART0                                 0x744c9cd8U
#define FIRMUP_PART1                                 0x450c5aecU
#define FIRMUP_PART2                                 0x3173bca9U
#define FIRMUP_PART3                                 0xa0b3d389U

#define RPMB_SRV_INDEX                               0x4
#define RPMB_SRV_PART0                               0x004555daU
#define RPMB_SRV_PART1                               0x4a8e864eU
#define RPMB_SRV_PART2                               0x58284085U
#define RPMB_SRV_PART3                               0x29e5e718U

#define EFUSE_INDEX                                  0x5
#define EFUSE_PART0                                  0xc97a7f7dU
#define EFUSE_PART1                                  0x4851d659U
#define EFUSE_PART2                                  0xcbb079baU
#define EFUSE_PART3                                  0x598981f7U

typedef struct {
    uint32_t cmd;
    uint32_t addr_addr_h;
    uint32_t addr_addr_l;
    uint32_t ddr_data_len;
    uint32_t ddr_para_num;
    uint32_t channel_num;
    uint32_t mainkey_cnt;
} FILL_PART_HSM_DATA;
#endif
