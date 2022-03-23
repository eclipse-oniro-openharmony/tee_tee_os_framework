/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP driver common definition
 * Author: Hisilicon DSS
 * Create: 2019-07-07
 */

#ifndef HISI_HDCP_COMMON_H
#define HISI_HDCP_COMMON_H

#include <sre_typedef.h>
#include "tee_log.h"

/* common tools  */
#define HISI_HDCP_DEBUG(msg, ...) \
	do { \
		uart_printf_func("[HDCP]%s: "msg, __func__, ## __VA_ARGS__); \
	} while (0)

#define hdcp_check_and_return(condition, ret, level, msg, ...) \
	do { \
		if (condition) { \
			HISI_HDCP_##level(msg, ##__VA_ARGS__); \
			return ret; \
		} \
	} while (0)


#define TYPE_HDCP13 0
#define TYPE_HDCP22 1

/* HDCP and DP registers */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#define HDCP_BASE_ADDR 0xFF340000

#define HDCP13_SEED_ENABLE 0x3614
#define HDCP13_SEED        0x361C
#define HDCP13_KEY0_OFFSET 0x3620
#define HDCP13_KEY1_OFFSET 0x3624
#define HDCP_OFFSET_MAX    0x3610

#define HDCP22_KPF0_OFFSET 0x12300
#define HDCP22_KPF1_OFFSET 0x12304
#define HDCP22_KPF2_OFFSET 0x12308
#define HDCP22_KPF3_OFFSET 0x1230C
#define HDCP22_DUK0_OFFSET 0x12310
#define HDCP22_DUK1_OFFSET 0x12314
#define HDCP22_DUK2_OFFSET 0x12318
#define HDCP22_DUK3_OFFSET 0x1231C

#define HDCP22_TRNG_RESEED_OFFSET 0x11000
#define HDCP22_TRNG_MODE_OFFSET   0x11008
#define HDCP22_TRNG_SMODE_OFFSET  0x1100C
#define HDCP22_TRNG_ISTAT_OFFSET  0x11014

#define HDCP_DPC_SEC_ENABLE  0x12000
#define HDCP13_AUTHEN_ENABLE 0xe00

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)

#define HDCP_BASE_ADDR 0xF8500000

#define HDCP13_SEED_ENABLE 0x3614
#define HDCP13_SEED        0x361C
#define HDCP13_KEY0_OFFSET 0x3620
#define HDCP13_KEY1_OFFSET 0x3624
#define HDCP_OFFSET_MAX    0x3610

#define HDCP22_KPF0_OFFSET 0x42300
#define HDCP22_KPF1_OFFSET 0x42304
#define HDCP22_KPF2_OFFSET 0x42308
#define HDCP22_KPF3_OFFSET 0x4230C
#define HDCP22_DUK0_OFFSET 0x42310
#define HDCP22_DUK1_OFFSET 0x42314
#define HDCP22_DUK2_OFFSET 0x42318
#define HDCP22_DUK3_OFFSET 0x4231C

#define HDCP22_TRNG_RESEED_OFFSET 0x41000
#define HDCP22_TRNG_MODE_OFFSET   0x41008
#define HDCP22_TRNG_SMODE_OFFSET  0x4100C
#define HDCP22_TRNG_ISTAT_OFFSET  0x41014

#define HDCP_DPC_SEC_ENABLE  0x42000
#define HDCP13_AUTHEN_ENABLE 0xe00

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define HDCP_BASE_ADDR 0xF8400000
#define HDCP_OFFSET_MAX 0x0700

#define HDCP_CFG 0x0600
#define HDCP2X_KS0 0x0604
#define HDCP2X_KS1 0x0608
#define HDCP2X_KS2 0x060C
#define HDCP2X_KS3 0x0610
#define HDCP2X_RIV0 0x0614
#define HDCP2X_RIV1 0x0618
#define HDCP13_KS0 0x061C
#define HDCP13_KS1 0x0620
#define HDCP13_M00 0x0624
#define HDCP13_M01 0x0628
#define HDCP2X_LC128_0 0x0634
#define HDCP2X_LC128_1 0x0638
#define HDCP2X_LC128_2 0x063C
#define HDCP2X_LC128_3 0x0640

#define CFG_HDCP_MODE_HDCP13   (1u << 5)
#define CFG_HDCP_MODE_HDCP22   (2u << 5)
#define CFG_HDCP_START_ENCRYPT (1u << 4)
#define CFG_HDCP_AUTH_SUCCESS  (1u << 3)
#define CFG_HDCP_CTRL_NORMAL   (1u << 1)
#define CFG_HDCP_CTRL_WHITE    (2u << 1)
#define CFG_HDCP_CTRL_MASK     (3u << 1)
#define CFG_REPEATER_YES       (1u << 0)
#endif

/* HDCP & DP registers only use in baltimore */
#define HDCP_DSS_BASE_ADDR 0xF8481000
#define HDCP_DSS_OFFSET_MAX 0x1000

#define DP_RESET_OFFSET 0x28
#define DP_RESET_MASK (1u << 16)

#define DPTX_RST_CTRL 0x700
#define DPTX_SST0_RST_N (1u << 0)
#define DPTX_SST1_RST_N (1u << 1)
#define DPTX_MST_RST_N  (1u << 2)
#define DPTX_HDCP_RST_N (1u << 3)
#define DPTX_AUX_RST_N  (1u << 4)
#define DPTX_PHY_RST_N  (1u << 5)
#define DPTX_RST_CTRL_ALL (DPTX_SST0_RST_N | \
		DPTX_SST1_RST_N | \
		DPTX_MST_RST_N | \
		DPTX_HDCP_RST_N | \
		DPTX_AUX_RST_N | \
		DPTX_PHY_RST_N)


extern void uart_printf_func(const char *fmt, ...);

static inline uint32_t MinT(uint32_t a, uint32_t b)
{
    return ((a > b) ? b : a);
}

static inline void udelay(uint32_t usec)
{
    uint64_t i;

    for (i = 0; i < 1000 * (uint64_t)usec; i++) {
        asm("nop");
    }
}

int hdcp_get_value(unsigned int offset);
int hdcp_set_reg(unsigned int reg_value, unsigned int offset);
int hdcp_get_dss_value(unsigned int offset);
int hdcp_set_dss_reg(unsigned int reg_value, unsigned int offset);

#endif
