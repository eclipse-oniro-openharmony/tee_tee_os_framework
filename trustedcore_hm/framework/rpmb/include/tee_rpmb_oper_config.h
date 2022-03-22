/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rpmb operation config
 * Create: 2020-02-13
 */
#ifndef RPMB_TEE_RPMB_OPER_CONFIG_H
#define RPMB_TEE_RPMB_OPER_CONFIG_H
#include <tee_defines.h>

#define RPMB_CHIP_VERSION_01     0x5a5a0001U
#define RPMB_EMMC_BITMAP_DEF     0x03U
#define RPMB_EMMC_BITMAP_BIT_MAX 32U

#define RPMB_AGENT_BUFF_SIZE (4U * 1024U)
#define RPMB_AGENT_BUFF_NUM_MAX 8U

#define RPMB_BUF_RES_BLK 2U

#define RPMB_UFS_MAX_WRITE_BLKCNT 32U

enum rpmb_key_type {
    RPMB_KEY_UNKOWN = 0,
    RPMB_MANAGE_KEY,
    RPMB_DERIVE_KEY,
    RPMB_ACCESS_KEY,
    RPMB_M_KEY,
    RPMB_HSM_KEY
};

/* Data Frame Size in RPMB */
#define RPMB_STUFF_SIZE         196U
#define RPMB_KEY_MAC_SIZE       32U
#define RPMB_DATA_SIZE          256U
#define RPMB_NONCE_SIZE         16U
#define RPMB_WRITE_COUNTER_SIZE 4U
#define RPMB_ADDRESS_SIZE       2U
#define RPMB_BLOCKCOUNT_SIZE    2U
#define RPMB_RESULT_SIZE        2U
#define RPMB_TYPE_SIZE          2U
#define RPMB_FRAME_SIZE         512U
#define RPMB_DATA_OFFSET           (RPMB_STUFF_SIZE + RPMB_KEY_MAC_SIZE)
#define RPMB_MAC_PROTECT_DATA_SIZE (RPMB_FRAME_SIZE - RPMB_DATA_OFFSET)
struct rpmb_data_frame {
    uint8_t stuff_data_bytes[RPMB_STUFF_SIZE];
    uint8_t key_mac[RPMB_KEY_MAC_SIZE];
    uint8_t data[RPMB_DATA_SIZE];
    uint8_t nonce[RPMB_NONCE_SIZE];
    uint8_t wr_counter[RPMB_WRITE_COUNTER_SIZE];
    uint8_t address[RPMB_ADDRESS_SIZE];
    uint8_t blk_count[RPMB_BLOCKCOUNT_SIZE];
    uint8_t result[RPMB_RESULT_SIZE];
    uint8_t type[RPMB_TYPE_SIZE];
};

struct rpmb_key_info {
    uint8_t *key;
    uint32_t keysize;
};

#define RPMB_MSG_AUTH_KEY_SIZE 8U
struct rpmb_partition_info_mtk {
    uint32_t magic;             /* magic number */
    uint32_t version;           /* version */
    uint32_t msg_auth_key[RPMB_MSG_AUTH_KEY_SIZE];   /* size of message auth key is 32bytes(256 bits) */
    uint32_t rpmb_size;         /* size of rpmb partition */
    uint32_t emmc_rel_wr_sec_c; /* emmc ext_csd[222] */
    uint32_t error_code;
    uint32_t readout_magic;
    uint32_t resv1;
    uint32_t resv2;
    uint32_t resv3;
};

#define RPMB_EMMC_CID_SIZE       32U
struct rpmb_devinfo {
    uint8_t cid[RPMB_EMMC_CID_SIZE]; /* eMMC card ID */
    uint8_t rpmb_size_mult; /* EXT CSD-slice 168 "RPMB Size" */
    uint8_t rel_wr_sec_cnt; /* EXT CSD-slice 222 "Reliable Write Sector Count" */
    uint16_t tmp;
    uint32_t blk_size; /* RPMB blocksize */
    uint32_t max_blk_idx;          /* The highest block index supported by current device */
    uint32_t access_start_blk_idx; /* The start block index SecureOS can access */
    uint32_t access_total_blk; /* The total blocks SecureOS can access */
    uint32_t tmp2;
    uint32_t mdt;             /* 1: EMMC 2: UFS */
    uint32_t support_bit_map; /* the device's support bit map, for example, if support 1,2,32, value is 0x80000003 */
    uint32_t version; /* High 16bit 0x5a5a means support_bit_map is valid, low 16bit is version, starting from 0x1 */
    uint32_t tmp3;
};


TEE_Result rpmb_reset_permission_in_tbl(const TEE_UUID *uuid);
TEE_Result rpmb_status_permission_in_tbl(const TEE_UUID *uuid);
TEE_Result rpmb_get_ta_threshold_in_tbl(const TEE_UUID *uuid, uint32_t *ta_threshold);
uint32_t rpmb_get_all_ta_threshold_without_fingerprint(void);
void tee_rpmb_get_key_type(uint32_t *key_type);
void tee_rpmb_get_meta_type(uint32_t *meta_type);
bool is_fingerprint(const TEE_UUID *uuid);
TEE_Result tee_rpmb_calc_mac(const struct rpmb_data_frame *datafrms, uint16_t blkcnt,
                             const struct rpmb_key_info *rpmb_key, uint8_t *mac, uint32_t macsize);
TEE_Result tee_rpmb_key_prepare(uint8_t **rpmb_key, uint32_t *key_size);
TEE_Result tee_rpmb_get_devinfo(struct rpmb_devinfo *rdi);
uint16_t tee_rpmb_get_max_access_cnt(const struct rpmb_devinfo *rdi);
void tee_rpmb_init_agent_buff_size(uint32_t size);
uint32_t rpmb_get_agent_buff_size(void);
#endif
