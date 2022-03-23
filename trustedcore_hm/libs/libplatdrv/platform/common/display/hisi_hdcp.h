/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */

#ifndef TEE_HDCP_H

#define TEE_HDCP_H

#include <register_ops.h> // writel
#include "tee_log.h"
#include "securec.h"

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#define HDCP_BASE_ADDR  0xFF340000

#define HDCP13_SEED_ENABLE  0x3614
#define HDCP13_SEED			0x361C
#define HDCP13_KEY0_OFFSET	0x3620
#define HDCP13_KEY1_OFFSET	0x3624
#define HDCP_OFFSET_MAX      0x3610

#define HDCP22_KPF0_OFFSET	0x12300
#define HDCP22_KPF1_OFFSET	0x12304
#define HDCP22_KPF2_OFFSET	0x12308
#define HDCP22_KPF3_OFFSET	0x1230C
#define HDCP22_DUK0_OFFSET	0x12310
#define HDCP22_DUK1_OFFSET	0x12314
#define HDCP22_DUK2_OFFSET	0x12318
#define HDCP22_DUK3_OFFSET	0x1231C

#define HDCP22_TRNG_RESEED_OFFSET	0x11000
#define HDCP22_TRNG_MODE_OFFSET	0x11008
#define HDCP22_TRNG_SMODE_OFFSET	0x1100C
#define HDCP22_TRNG_ISTAT_OFFSET	0x11014

#define HDCP_DPC_SEC_ENABLE 0x12000
#define HDCP13_AUTHEN_ENABLE 0xe00

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)

#define HDCP_BASE_ADDR  0xF8500000

#define HDCP13_SEED_ENABLE   0x3614
#define HDCP13_SEED          0x361C
#define HDCP13_KEY0_OFFSET   0x3620
#define HDCP13_KEY1_OFFSET   0x3624
#define HDCP_OFFSET_MAX      0x3610

#define HDCP22_KPF0_OFFSET   0x42300
#define HDCP22_KPF1_OFFSET   0x42304
#define HDCP22_KPF2_OFFSET   0x42308
#define HDCP22_KPF3_OFFSET   0x4230C
#define HDCP22_DUK0_OFFSET   0x42310
#define HDCP22_DUK1_OFFSET   0x42314
#define HDCP22_DUK2_OFFSET   0x42318
#define HDCP22_DUK3_OFFSET   0x4231C

#define HDCP22_TRNG_RESEED_OFFSET    0x41000
#define HDCP22_TRNG_MODE_OFFSET      0x41008
#define HDCP22_TRNG_SMODE_OFFSET     0x4100C
#define HDCP22_TRNG_ISTAT_OFFSET     0x41014

#define HDCP_DPC_SEC_ENABLE  0x42000
#define HDCP13_AUTHEN_ENABLE 0xe00

#endif

#define BLOCK_SIZE_MAX 0x7D000  //500K

typedef struct hdcp13_key {
	uint32_t key_l;
	uint32_t key_h;
} hdcp13_key_t;

typedef struct hdcp13_all_key {
    hdcp13_key_t aksv;
    hdcp13_key_t dpk[40];
    uint16_t seed;
}hdcp13_all_key_t;

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

int hdcp13_key_all_set(hdcp13_all_key_t *key_all);
int hdcp22_key_set(hdcp22_key_t* duk, hdcp22_key_t* kpf);
int hdcp_dp_enable(unsigned int dp_flag);
int hdcp_get_value(unsigned int offset);
int hdcp_set_reg(unsigned int reg_value, unsigned int offset);

#endif

