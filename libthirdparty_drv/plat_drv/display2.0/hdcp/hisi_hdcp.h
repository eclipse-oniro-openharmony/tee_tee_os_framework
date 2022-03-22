/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_HDCP_H
#define HISI_HDCP_H

#include "hisi_hdcp_common.h"

#define BLOCK_SIZE_MAX 0x7D000 // 500K
#define HDCP13_DPK_SIZE 40
#define EOK 0

#define HDCP22_KS_SIZE 4
#define HDCP22_RIV_SIZE 2
#define HDCP22_LC128_SIZE 4

typedef struct hdcp13_key {
	uint32_t key_l;
	uint32_t key_h;
} hdcp13_key_t;

typedef struct hdcp13_all_key {
	hdcp13_key_t aksv;
	hdcp13_key_t dpk[HDCP13_DPK_SIZE];
	uint16_t seed;
} hdcp13_all_key_t;

typedef struct hdcp22_key {
	uint32_t key_l;
	uint32_t key_m1;
	uint32_t key_m2;
	uint32_t key_h;
} hdcp22_key_t;

struct session_identity {
	uint32_t len;
	char val[1];
};

struct soft_hdcp22_key {
	uint32_t ks[HDCP22_KS_SIZE];
	uint32_t riv[HDCP22_RIV_SIZE];
	uint32_t lc128[HDCP22_LC128_SIZE];
};

struct soft_hdcp13_key {
	uint64_t m0;
	uint64_t ks;
};

struct soft_hdcp_cfg {
	uint8_t type;
	uint8_t is_repeater;
};

enum hdcp_ioctl_cmd {
	CMD_SOFT_RESET_HDCP_MODULE = 0,
	CMD_SOFT_RESET_HDCP_REGS,
	CMD_SOFT_SET_HDCP22_KEY,
	CMD_SOFT_SET_HDCP13_KEY,
	CMD_SOFT_SET_HDCP_CFG,
	CMD_SOFT_DISABLE_ENCRYPT,
	CMD_SOFT_ENABLE_ENCRYPT,
	CMD_SOFT_DISABLE_OUTPUT,
	CMD_SOFT_DISABLE_OUTPUT_PLAINTEXT,
	CMD_SOFT_SET_HDCP_CFG_WHITE,
	CMD_SOFT_ENABLE_ENCRYPT_WHITE,
	CMD_HDCP_DPCD_W,
	CMD_HDCP_DPCD_R
};

int hdcp13_key_all_set(hdcp13_all_key_t *key_all);
int hdcp22_key_set(hdcp22_key_t *duk, hdcp22_key_t *kpf);
int hdcp_dp_enable(unsigned int dp_flag);
int hdcp_ioctl(unsigned int cmd_id, unsigned int data, void *buf, unsigned int size);

#endif

