/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_hdcp.h"
#include "hisi_hdcp_dp.h"
#include <pthread.h>

#define UINT_BITS 32
#define UINT_MAX 0xFFFFFFFF
#define HDCP_RESET_DELAY (10 * 1000) // 10ms

pthread_mutex_t g_hdcp_pthread_lock = PTHREAD_MUTEX_INITIALIZER;

int hdcp13_key_all_set(hdcp13_all_key_t *key_all)
{
	(void)key_all;
	return 0;
}

int hdcp22_key_set(hdcp22_key_t *duk, hdcp22_key_t *kpf)
{
	(void)duk;
	(void)kpf;
	return 0;
}

int hdcp_dp_enable(unsigned int dp_flag)
{
	(void)dp_flag;
	return 0;
}

static void soft_reset_hdcp_module(void)
{
	uint32_t val;

	val = hdcp_get_value(DPTX_RST_CTRL);

	/* set 0x700 bit3 to 0 */
	val &= (~DPTX_HDCP_RST_N);
	hdcp_set_reg(val, DPTX_RST_CTRL);

	udelay(HDCP_RESET_DELAY);

	/* set 0x700 bit3 to 1 */
	val = hdcp_get_value(DPTX_RST_CTRL);
	val |= DPTX_HDCP_RST_N;
	hdcp_set_reg(val, DPTX_RST_CTRL);

	HISI_HDCP_DEBUG("set reg: reset hdcp module finish\n");
}

static void soft_reset_hdcp_regs(void)
{
	/* reset hdcp22_ks */
	hdcp_set_reg(0x0, HDCP2X_KS0);
	hdcp_set_reg(0x0, HDCP2X_KS1);
	hdcp_set_reg(0x0, HDCP2X_KS2);
	hdcp_set_reg(0x0, HDCP2X_KS3);

	/* reset hdcp22_riv */
	hdcp_set_reg(0x0, HDCP2X_RIV0);
	hdcp_set_reg(0x0, HDCP2X_RIV1);

	/* reset hdcp22_lc128 */
	hdcp_set_reg(0x0, HDCP2X_LC128_0);
	hdcp_set_reg(0x0, HDCP2X_LC128_1);
	hdcp_set_reg(0x0, HDCP2X_LC128_2);
	hdcp_set_reg(0x0, HDCP2X_LC128_3);

	/* reset hdcp13_ks */
	hdcp_set_reg(0x0, HDCP13_KS0);
	hdcp_set_reg(0x0, HDCP13_KS1);

	/* reset hdcp13_m0 */
	hdcp_set_reg(0x0, HDCP13_M00);
	hdcp_set_reg(0x0, HDCP13_M01);

	/* reset hdcp_cfg */
	hdcp_set_reg((CFG_HDCP_MODE_HDCP13 | CFG_HDCP_CTRL_NORMAL), HDCP_CFG);

	HISI_HDCP_DEBUG("set reg: reset hdcp registers finish\n");
}

static int soft_set_hdcp22_key(struct soft_hdcp22_key *key, unsigned int size)
{
	if (size != sizeof(struct soft_hdcp22_key)) {
		HISI_HDCP_DEBUG("size %d is invalid\n", size);
		return -1;
	}

	/* set hdcp22_ks */
	hdcp_set_reg(key->ks[3], HDCP2X_KS0);
	hdcp_set_reg(key->ks[2], HDCP2X_KS1);
	hdcp_set_reg(key->ks[1], HDCP2X_KS2);
	hdcp_set_reg(key->ks[0], HDCP2X_KS3);

	/* set hdcp22_riv */
	hdcp_set_reg(key->riv[1], HDCP2X_RIV0);
	hdcp_set_reg(key->riv[0], HDCP2X_RIV1);

	/* set hdcp22_lc128 */
	hdcp_set_reg(key->lc128[3], HDCP2X_LC128_0);
	hdcp_set_reg(key->lc128[2], HDCP2X_LC128_1);
	hdcp_set_reg(key->lc128[1], HDCP2X_LC128_2);
	hdcp_set_reg(key->lc128[0], HDCP2X_LC128_3);

	HISI_HDCP_DEBUG("set reg: set hdcp22 key registers finish\n");
	return 0;
}

static int soft_set_hdcp13_key(struct soft_hdcp13_key *key, unsigned int size)
{
	if (size != sizeof(struct soft_hdcp13_key)) {
		HISI_HDCP_DEBUG("size %u is invalid\n", size);
		return -1;
	}

	/* set hdcp13_m0 */
	hdcp_set_reg((uint32_t)(key->m0 & UINT_MAX), HDCP13_M00);
	hdcp_set_reg((uint32_t)(key->m0 >> UINT_BITS), HDCP13_M01);

	/* set hdcp13_ks */
	hdcp_set_reg((uint32_t)(key->ks & UINT_MAX), HDCP13_KS0);
	hdcp_set_reg((uint32_t)(key->ks >> UINT_BITS), HDCP13_KS1);

	HISI_HDCP_DEBUG("set reg: set hdcp13 key registers finish\n");
	return 0;
}

/* set hdcp_cfg after authentication success */
static int soft_set_hdcp_cfg(struct soft_hdcp_cfg *config, unsigned int size)
{
	uint32_t val;

	if (size != sizeof(struct soft_hdcp_cfg)) {
		HISI_HDCP_DEBUG("size %d is invalid\n", size);
		return -1;
	}

	if (config->type == TYPE_HDCP13)
		val = CFG_HDCP_MODE_HDCP13;
	else
		val = CFG_HDCP_MODE_HDCP22;

	val |= (CFG_HDCP_AUTH_SUCCESS | CFG_HDCP_CTRL_NORMAL);

	if (config->is_repeater != 0)
		val |= CFG_REPEATER_YES;

	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: after authen ok, set hdcp cfg register finish\n");
	return 0;
}

static void soft_disable_encryption(void)
{
	uint32_t val = hdcp_get_value(HDCP_CFG);

	val &= (~CFG_HDCP_START_ENCRYPT);
	val &= (~CFG_HDCP_CTRL_MASK);
	val |= CFG_HDCP_CTRL_NORMAL;
	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: disable encryption\n");
}


static void soft_enable_encryption(void)
{
	uint32_t val = hdcp_get_value(HDCP_CFG);

	val |= CFG_HDCP_START_ENCRYPT;
	val &= (~CFG_HDCP_CTRL_MASK);
	val |= CFG_HDCP_CTRL_NORMAL;
	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: enable encryption\n");
}

static void soft_disable_output(void)
{
	uint32_t val = hdcp_get_value(HDCP_CFG);

	val &= (~CFG_HDCP_CTRL_MASK);
	val |= CFG_HDCP_CTRL_WHITE;
	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: disable output\n");
}

static void soft_disable_output_plaintext(void)
{
	uint32_t val = hdcp_get_value(HDCP_CFG);

	val &= (~CFG_HDCP_START_ENCRYPT);
	val &= (~CFG_HDCP_CTRL_MASK);
	val |= CFG_HDCP_CTRL_WHITE;
	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: disable output plaintext\n");
}

static int soft_set_hdcp_cfg_white(struct soft_hdcp_cfg *config, unsigned int size)
{
	uint32_t val;

	if (size != sizeof(struct soft_hdcp_cfg)) {
		HISI_HDCP_DEBUG("size %d is invalid\n", size);
		return -1;
	}

	if (config->type == TYPE_HDCP13)
		val = CFG_HDCP_MODE_HDCP13;
	else
		val = CFG_HDCP_MODE_HDCP22;

	val |= (CFG_HDCP_AUTH_SUCCESS | CFG_HDCP_CTRL_WHITE);

	if (config->is_repeater != 0)
		val |= CFG_REPEATER_YES;

	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: soft set hdcp cfg white\n");
	return 0;
}

static void soft_enable_encryption_white(void)
{
	uint32_t val = hdcp_get_value(HDCP_CFG);

	val |= CFG_HDCP_START_ENCRYPT;
	val &= (~CFG_HDCP_CTRL_MASK);
	val |= CFG_HDCP_CTRL_WHITE;
	hdcp_set_reg(val, HDCP_CFG);
	HISI_HDCP_DEBUG("set reg: soft enable encryption white\n");
}


static bool soft_is_dp_on(void)
{
    uint32_t val = hdcp_get_dss_value(DP_RESET_OFFSET);

    /* bit16: 0-dp on, 1-dp off */
    return ((val & DP_RESET_MASK) == 0);
}

int hdcp_ioctl(unsigned int cmd_id, unsigned int data, void *buf, unsigned int size)
{
	int ret = 0;

	hdcp_check_and_return((buf == NULL), -1, DEBUG, "buf is null\n");
	hdcp_check_and_return((soft_is_dp_on() == false), -1, DEBUG, "dp is off\n");

	if (pthread_mutex_lock(&g_hdcp_pthread_lock) != SRE_OK) {
		HISI_HDCP_DEBUG("wait hdcp_lock failed!\n");
		return ret;
	}

	switch ((enum hdcp_ioctl_cmd)cmd_id) {
	case CMD_SOFT_RESET_HDCP_MODULE:
		soft_reset_hdcp_module();
		break;
	case CMD_SOFT_RESET_HDCP_REGS:
		soft_reset_hdcp_regs();
		break;
	case CMD_SOFT_SET_HDCP22_KEY:
		ret = soft_set_hdcp22_key((struct soft_hdcp22_key *)buf, size);
		break;
	case CMD_SOFT_SET_HDCP13_KEY:
		ret = soft_set_hdcp13_key((struct soft_hdcp13_key *)buf, size);
		break;
	case CMD_SOFT_SET_HDCP_CFG:
		ret = soft_set_hdcp_cfg((struct soft_hdcp_cfg *)buf, size);
		break;
	case CMD_SOFT_DISABLE_ENCRYPT:
		soft_disable_encryption();
		break;
	case CMD_SOFT_ENABLE_ENCRYPT:
		soft_enable_encryption();
		break;
	case CMD_SOFT_DISABLE_OUTPUT:
		soft_disable_output();
		break;
	case CMD_SOFT_DISABLE_OUTPUT_PLAINTEXT:
		soft_disable_output_plaintext();
		break;
	case CMD_SOFT_SET_HDCP_CFG_WHITE:
		ret = soft_set_hdcp_cfg_white((struct soft_hdcp_cfg *)buf, size);
		break;
	case CMD_SOFT_ENABLE_ENCRYPT_WHITE:
		soft_enable_encryption_white();
		break;
	case CMD_HDCP_DPCD_W:
		ret = dptx_write_bytes_to_dpcd(data, (uint8_t *)buf, size);
		break;
	case CMD_HDCP_DPCD_R:
		ret = dptx_read_bytes_from_dpcd(data, (uint8_t *)buf, size);
		break;
	default:
		HISI_HDCP_DEBUG("invalid hdcp ioctl cmd\n");
		break;
	}

	if (pthread_mutex_unlock(&g_hdcp_pthread_lock) != SRE_OK) {
		HISI_HDCP_DEBUG("wait hdcp_unlock failed!\n");
		return ret;
	}

	return ret;
}




