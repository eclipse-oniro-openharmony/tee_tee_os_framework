#ifndef _I2C_RESOURCE_H_
#define _I2C_RESOURCE_H_

#include <i2c.h>
#include <tzpc.h>
#include "soc_acpu_baseaddr_interface.h"

#define REG_BASE_I2C7 SOC_ACPU_I2C7_BASE_ADDR

#define I2C_AP_DOMAIN 0
#define I2C_IOMCU_DOMAIN 1

#define I2C_NO_NEED_SWITCH_SEC_FLAG 0
#define I2C_NEED_SWITCH_SEC_FLAG 1

#define I2C_FAST_SPEED (1 << 2)
#define I2C_STD_SPEED (1 << 1)

struct i2c_tzpc_iomcu_domain_data {
	u32 addr;
	u32 offset;
	u32 mask_bit;
};

struct i2c_tzpc_ap_domain_map {
	u32 tzpc_idx;
};

struct i2c_reset_data {
	u32 enable;
	u32 disable;
	u32 status;
	u32 bit;
};

struct i2c_resource {
	u32 bus_id;
	u32 base;
	u32 clk_rate; /* kHz */
	u32 speed_mode;
	struct i2c_reset_data reset_data;
	u32 domain;
	u32 tzpc_flag;
	union {
		struct i2c_tzpc_iomcu_domain_data tzpc_info;
		struct i2c_tzpc_ap_domain_map tzpc_map;
	} tzpc_data;
};

static struct i2c_resource i2c_res[] = {
	[0] = {
		.bus_id = 7,
		.base = REG_BASE_I2C7,
#if (WITH_CHIP_HI3670 == TRUSTEDCORE_CHIP_CHOOSE)   || \
	(WITH_CHIP_HI3680 == TRUSTEDCORE_CHIP_CHOOSE)   || \
	(WITH_CHIP_KIRIN990 == TRUSTEDCORE_CHIP_CHOOSE) || \
	(WITH_CHIP_ORLANDO == TRUSTEDCORE_CHIP_CHOOSE)  || \
	(WITH_CHIP_HI6260 == TRUSTEDCORE_CHIP_CHOOSE)
		.clk_rate = 107000,
#elif (WITH_CHIP_BALTIMORE == TRUSTEDCORE_CHIP_CHOOSE)
		.clk_rate = 111000,
#elif (WITH_CHIP_DENVER == TRUSTEDCORE_CHIP_CHOOSE) || \
	(WITH_CHIP_LAGUNA == TRUSTEDCORE_CHIP_CHOOSE)   || \
	(WITH_CHIP_BURBANK == TRUSTEDCORE_CHIP_CHOOSE)
		.clk_rate = 109000,
#else
#endif
		.speed_mode = I2C_FAST_SPEED,
		.reset_data.enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x60,
		.reset_data.disable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x64,
		.reset_data.status = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x68,
		.reset_data.bit = 0x1 << 14,
		.domain = I2C_AP_DOMAIN,
		.tzpc_flag = I2C_NEED_SWITCH_SEC_FLAG,
		.tzpc_data.tzpc_map.tzpc_idx = TZ_I2C7,
	},
};

#endif
