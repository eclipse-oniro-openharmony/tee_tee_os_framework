/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "register_ops.h"
#include "tee_log.h" /* uart_printf_func */
#include "hisi_hdcp.h"

#define HDCP_KEYSET_DELAY 10

static int hdcp13_key_set(hdcp13_key_t *key)
{
	if (key == NULL) {
		uart_printf_func("%s: the key is NULL\n", __func__);
		return -1;
	}
	writel(key->key_l, HDCP_BASE_ADDR + HDCP13_KEY1_OFFSET);
	writel(key->key_h, HDCP_BASE_ADDR + HDCP13_KEY0_OFFSET);
	return 0;
}

static int hdcp22_trng_init(void)
{
	writel(0x000a0100, HDCP_BASE_ADDR + HDCP22_TRNG_SMODE_OFFSET);
	writel(0x00, HDCP_BASE_ADDR + HDCP22_TRNG_MODE_OFFSET);
	writel(0x02, HDCP_BASE_ADDR + HDCP22_TRNG_RESEED_OFFSET);
	writel(0x01, HDCP_BASE_ADDR + HDCP22_TRNG_RESEED_OFFSET);
	writel(0x03, HDCP_BASE_ADDR + HDCP22_TRNG_ISTAT_OFFSET);
	return 0;
}

static int hdcp22_duk_set(hdcp22_key_t *duk)
{
	if (duk == NULL) {
		uart_printf_func("%s: duk is NULL\n", __func__);
		return -1;
	}
	writel(duk->key_l, HDCP_BASE_ADDR + HDCP22_DUK0_OFFSET);
	writel(duk->key_m1, HDCP_BASE_ADDR + HDCP22_DUK1_OFFSET);
	writel(duk->key_m2, HDCP_BASE_ADDR + HDCP22_DUK2_OFFSET);
	writel(duk->key_h, HDCP_BASE_ADDR + HDCP22_DUK3_OFFSET);
	return 0;
}

static int hdcp22_pkf_set(hdcp22_key_t *kpf)
{
	if (kpf == NULL) {
		uart_printf_func("%s: kpf is NULL\n", __func__);
		return -1;
	}
	writel(kpf->key_l, HDCP_BASE_ADDR + HDCP22_KPF0_OFFSET);
	writel(kpf->key_m1, HDCP_BASE_ADDR + HDCP22_KPF1_OFFSET);
	writel(kpf->key_m2, HDCP_BASE_ADDR + HDCP22_KPF2_OFFSET);
	writel(kpf->key_h, HDCP_BASE_ADDR + HDCP22_KPF3_OFFSET);
	return 0;
}

int hdcp13_key_all_set(hdcp13_all_key_t *key_all)
{
	uint32_t dpk13_size = 0;

	if (key_all == NULL) {
		uart_printf_func("%s: the point is NULL\n", __func__);
		return -1;
	}

	if (hdcp13_key_set(&(key_all->aksv))) {
		uart_printf_func("%s: hdcp13 aksv write failed\n", __func__);
		return -1;
	}

	udelay(HDCP_KEYSET_DELAY);
	writel(0x00, HDCP_BASE_ADDR + HDCP13_SEED_ENABLE);

	while (dpk13_size < HDCP13_DPK_SIZE) {
		if (hdcp13_key_set(&(key_all->dpk[dpk13_size]))) {
			uart_printf_func("%s: hdcp13 dpk write failed\n", __func__);
			return -1;
		}
		udelay(HDCP_KEYSET_DELAY);
		dpk13_size++;
	}
	return 0;
}

int hdcp22_key_set(hdcp22_key_t *duk, hdcp22_key_t *kpf)
{
	if ((duk == NULL) || (kpf == NULL)) {
		uart_printf_func("%s: the point is NULL\n", __func__);
		return -1;
	}
	hdcp22_pkf_set(kpf);
	hdcp22_duk_set(duk);
	hdcp22_trng_init();
	return 0;
}

int hdcp_dp_enable(unsigned int dp_flag)
{
	uint32_t temp;

	if (dp_flag > 1) {
		uart_printf_func("%s: the param is invalid\n", __func__);
		return -1;
	}
	temp = readl(HDCP_BASE_ADDR + HDCP_DPC_SEC_ENABLE);
	temp = (temp & (~0x40)) | (dp_flag << 6);
	writel(temp, HDCP_BASE_ADDR + HDCP_DPC_SEC_ENABLE);
	return 0;
}

int hdcp_ioctl(unsigned int cmd_id, unsigned int data, void *buf, unsigned int size)
{
	(void)cmd_id;
	(void)data;
	(void)buf;
	(void)size;
	return 0;
}




