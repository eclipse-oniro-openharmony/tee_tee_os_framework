/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: teeos i3c driver code
 *              This program is support for I3C work. include control init,
 *              clock and timing set, read and write data from device.
 * Create: 2019-07-04
 */
#include "i3c.h"
#include <gpio.h>
#include <hisi_debug.h>
#include <tzpc.h>
#include <sre_sys.h>
#include <mem_page_ops.h>
#include <stdlib.h>
#include <register_ops.h> /* readl */

#include "libhwsecurec/securec.h"
#include "sre_syscalls_id_ext.h"
#include "sre_access_control.h"

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#include "kirin990_i3c_adapter.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "baltimore_i3c_adapter.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "denver_i3c_adapter.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "laguna_i3c_adapter.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BURBANK)
#include "burbank_i3c_adapter.h"
#else
#endif

#define I3C_WAIT_REG_STATUS_TIMES 10
#define I3C_WAIT_STATUS_INTERVAL 10
#define I3C_SPEED_HPERIOD 1000000

#define I3C_2BITS_MASK 0x3
#define I3C_BYTE_MASK 0xFF

#define I3C_OD_HCNT_MAX_VAL 0xFF
#define I3C_MAX_BUF_LEN (0xFFFF - 2) /* start and end msg */
#define I3C_INVALID_DEV_IDX 0xFF
#define I3C_MAX_MSG_NUM 2
#define I3C_WRITE_BUF_THRESHOLD 4
#define I3C_WRITE_BUF_STAT_REG_MASK 0x1F
#define I3C_WAIT_STATUS_TIMEOUT 100000

static struct i3c_adapter *i3c_get_adapter(u32 bus_num)
{
	u32 i;
	u32 max;

	max = sizeof(i3c_adaps) / sizeof(struct i3c_adapter);
	for (i = 0; i < max; i++) {
		if (i3c_adaps[i].bus_num != bus_num)
			continue;
		return &i3c_adaps[i];
	}

	HISI_PRINT_ERROR("i3c%u not avaliable\n", bus_num);

	return NULL;
}

static int set_tzpc_iomcu_domain(struct i3c_adapter *adap, u32 value)
{
	u32 data;

	data = hisi_readl(adap->tzpc_data.tzpc_info.addr +
		adap->tzpc_data.tzpc_info.offset);
	data &= ~(1 << adap->tzpc_data.tzpc_info.mask_bit);
	data |= value << adap->tzpc_data.tzpc_info.mask_bit;

	hisi_writel(data, adap->tzpc_data.tzpc_info.addr +
		adap->tzpc_data.tzpc_info.offset);

	HISI_PRINT_DEBUG("i3c bus %u set tzpc succ\n", adap->bus_num);

	return I3C_OK;
}

static inline int set_tzpc_ap_domain(struct i3c_adapter *adap, u32 value)
{
	return tzpc_cfg(adap->tzpc_data.tzpc_map.tzpc_idx, value);
}

static int i3c_tzpc_cfg(struct i3c_adapter *adap, u32 value)
{
	int ret;

	if (adap->tzpc_flag == NO_NEED_SWITCH_SEC_FLAG) {
		HISI_PRINT_DEBUG("i3c%u, no need to set sec\n", adap->bus_num);
		return I3C_OK;
	}

	switch (adap->domain) {
	case I3C_AP_DOMAIN:
		ret = set_tzpc_ap_domain(adap, value);
		break;
	case I3C_IOMCU_DOMAIN:
		ret = set_tzpc_iomcu_domain(adap, value);
		break;
	default:
		HISI_PRINT_ERROR("i3c%u, check domain %u\n",
			adap->bus_num, adap->domain);
		ret = I3C_ERROR;
		break;
	}

	return ret;
}

static void i3c_clk_enable(struct i3c_adapter *adap)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	unused(adap);
	return;
#else
	u32 val;
	int timeout = I3C_WAIT_REG_STATUS_TIMES;

	hisi_writel(BIT(adap->clk_bit), adap->clk_en_reg);
	do {
		val = hisi_readl(adap->clk_stat_reg);
		val &= BIT(adap->clk_bit);
	} while (!val && timeout--);
	if (timeout <= 0)
		HISI_PRINT_ERROR("i3c, enable clk failed\n");
#endif
}

static void i3c_clk_disable(struct i3c_adapter *adap)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	unused(adap);
	return;
#else
	hisi_writel(BIT(adap->clk_bit), adap->clk_dis_reg);
#endif
}

static void i3c_reset_controller(struct i3c_adapter *adap)
{
	u32 stat;
	int timeout = I3C_WAIT_REG_STATUS_TIMES;

	hisi_writel(BIT(adap->rst_bit), adap->rst_en_reg);
	do {
		stat = hisi_readl(adap->rst_stat_reg);
		stat &= BIT(adap->rst_bit);
	} while (!stat && timeout--);
	if (!stat && (timeout <= 0))
		HISI_PRINT_ERROR("i3c%u reset: enable failed\n", adap->bus_num);

	timeout = I3C_WAIT_REG_STATUS_TIMES;
	hisi_writel(BIT(adap->rst_bit), adap->rst_dis_reg);
	do {
		stat = hisi_readl(adap->rst_stat_reg);
		stat &= BIT(adap->rst_bit);
	} while (stat && timeout--);
	if (stat && (timeout <= 0))
		HISI_PRINT_ERROR("i3c%u reset: disable failed\n",
			adap->bus_num);
}

static void i3c_pinmux_switch(struct i3c_adapter *adap, u8 func)
{
	if (func == I3C_IO_FUNC_I3C) {
		gpio_set_mode(adap->scl_iomux_gpio, adap->iomux_i3c_val);
		gpio_set_mode(adap->sda_iomux_gpio, adap->iomux_i3c_val);
	}
	if (func == I3C_IO_FUNC_NORMAL) {
		gpio_set_mode(adap->scl_iomux_gpio, adap->iomux_normal_val);
		gpio_set_mode(adap->sda_iomux_gpio, adap->iomux_normal_val);
	}
}

static u8 i3c_dynaddr_add_parity(u8 addr)
{
	u32 i;
	u8 count = 0;
	u8 ret_addr;

	for (i = 0; i < I3C_SLAVE_ADDR_BITS; i++) {
		if ((addr >> i) & 0x1)
			count++;
	}

	if (count & 0x1)
		ret_addr = addr & (~(0x1 << I3C_SLAVE_ADDR_BITS));
	else
		ret_addr = addr | (0x1 << I3C_SLAVE_ADDR_BITS);

	return ret_addr;
}

static int i3c_scl_chk_param(struct i3c_adapter *adap, u32 input_khz)
{
	if (adap->scl_pp_freq > I3C_SCL_MAX_FREQ) {
		HISI_PRINT_ERROR("i3c%u scl freq is too high %u\n",
			adap->bus_num, adap->scl_pp_freq);
		return I3C_ERROR;
	}

	if (!input_khz) {
		HISI_PRINT_ERROR("i3c%u clk_rate is zero\n", adap->bus_num);
		return I3C_ERROR;
	}

	if (!adap->scl_pp_freq) {
		HISI_PRINT_ERROR("i3c%u scl scl_pp_freq is zero\n",
			adap->bus_num);
		return I3C_ERROR;
	}

	if (!adap->scl_od_freq) {
		HISI_PRINT_ERROR("i3c%u scl scl_od_freq is zero\n",
			adap->bus_num);
		return I3C_ERROR;
	}

	return I3C_OK;
}

static void i3c_scl_write_cnt(struct i3c_adapter *adap, u32 pp_hcnt,
	u32 od_hcnt, u32 pp_lcnt, u32 od_i3c_lcnt, u32 od_i2c_lcnt)
{
	/* PP_HCNT affects (broadcast 0x7E hcnt) & (Push-Pull hcnt) */
	hisi_writel((pp_hcnt << SOC_I3C_SCL_HCNT_TIMING_I3C_PP_HCNT_START) |
		(od_hcnt << SOC_I3C_SCL_HCNT_TIMING_I3C_OD_HCNT_START) |
		(od_hcnt << SOC_I3C_SCL_HCNT_TIMING_I2C_OD_HCNT_START),
		adap->baseaddr + I3C_SCL_HCNT_TIMING);
	/*
	 * PP LCNT affects (Push-Pull lcnt)
	 * OD LCNT affects (broadcast 0x7E lcnt)
	 */
	hisi_writel((pp_lcnt << SOC_I3C_SCL_LCNT_TIMING_I3C_PP_LCNT_START) |
		(od_i3c_lcnt << SOC_I3C_SCL_LCNT_TIMING_I3C_OD_LCNT_START) |
		(od_i2c_lcnt << SOC_I3C_SCL_LCNT_TIMING_I2C_OD_LCNT_START),
		adap->baseaddr + I3C_SCL_LCNT_TIMING);
	HISI_PRINT_INFO("i3c%u scl_cnt_set pp_hcnt = %u, pp_lcnt = %u\n",
		adap->bus_num, pp_hcnt, pp_lcnt);
	HISI_PRINT_INFO("i3c%u o_hcnt %u, od_i3c_lcnt = %u, od_i2c_lcnt %u\n",
		adap->bus_num, od_hcnt, od_i3c_lcnt, od_i2c_lcnt);
}

static int i3c_scl_cnt_set(struct i3c_adapter *adap, u32 input_khz)
{
	u32 od_cnt, od_hcnt, od_i3c_lcnt, od_i2c_lcnt, pp_hperiod;
	u32 pp_cnt, pp_hcnt, pp_lcnt, od_cnt_ns, hcnt_ns, i3c_od_lperiod;

	if (i3c_scl_chk_param(adap, input_khz))
		return I3C_ERROR;

	pp_cnt = input_khz / adap->scl_pp_freq + 1;
	od_cnt = input_khz / adap->scl_od_freq;

	pp_hcnt = pp_cnt / 2; /* 50% duty */
	pp_lcnt = pp_cnt - pp_hcnt;
	pp_hperiod = pp_hcnt * I3C_SPEED_HPERIOD / input_khz;
	/* i3c pp high & low period at least 32ns */
	if (pp_hperiod < I3C_PP_H_MIN) {
		HISI_PRINT_ERROR("i3c%u pp mode timing out of constraint\n",
			adap->bus_num);
		HISI_PRINT_ERROR(
			"p_hcnt %u, p_lcnt %u, clk %ukHz, p_freq %ukHz\n",
			pp_hcnt, pp_lcnt, input_khz, adap->scl_pp_freq);
		return I3C_ERROR;
	}
	od_cnt_ns = (adap->scl_od_freq >= I3C_SCL_FREQ_1M) ?
		(I3C_I2C_FMP_TLOW_MIN_NS + I3C_I2C_FMP_THIGH_MIN_NS) :
		(I3C_I2C_FM_TLOW_MIN_NS + I3C_I2C_FM_THIGH_MIN_NS);
	hcnt_ns = (adap->scl_od_freq >= I3C_SCL_FREQ_1M) ?
		I3C_I2C_FMP_THIGH_MIN_NS : I3C_I2C_FM_THIGH_MIN_NS;
	od_hcnt = (u32)((od_cnt * hcnt_ns) / od_cnt_ns);
	od_i3c_lcnt = od_cnt - od_hcnt;
	if (od_hcnt >= I3C_OD_HCNT_MAX_VAL) {
		od_hcnt = I3C_OD_HCNT_MAX_VAL;
		od_i3c_lcnt = I3C_OD_HCNT_MAX_VAL;
	}
	od_i2c_lcnt = od_cnt - od_hcnt;

	i3c_od_lperiod = od_i3c_lcnt * I3C_SPEED_HPERIOD / input_khz;
	/* i3c od low period at least 200ns */
	if (i3c_od_lperiod < I3C_OD_L_MIN) {
		HISI_PRINT_ERROR("i3c%u pp_hcnt timing out of constraint\n",
			adap->bus_num);
		HISI_PRINT_ERROR(
			"o_hcnt %u, o_lcnt %u, clk %ukHz, o_freq %ukHz\n",
			od_hcnt, od_i3c_lcnt, input_khz, adap->scl_od_freq);
		return I3C_ERROR;
	}

	i3c_scl_write_cnt(adap, pp_hcnt, od_hcnt, pp_lcnt, od_i3c_lcnt,
		od_i2c_lcnt);

	return I3C_OK;
}

static int i3c_adapter_init(struct i3c_adapter *adap)
{
	u32 input_clock_khz = adap->clk_rate;
	int ret;
	u32 i;
	u32 val;

	i3c_reset_controller(adap);

	/* disable i3c */
	hisi_writel(0x0, adap->baseaddr + I3C_DEVICE_CTRL);

	/* config scl hcnt & lcnt */
	ret = i3c_scl_cnt_set(adap, input_clock_khz);
	if (ret < 0) {
		HISI_PRINT_ERROR("i3c%u scl_cnt_set error\n", adap->bus_num);
		return ret;
	}

	/* enable i3c; add broadcast 0x7e before private rw */
	hisi_writel(((u32)0x1 << SOC_I3C_DEVICE_CTRL_ENABLE_START) |
		((u32)0x0 << SOC_I3C_DEVICE_CTRL_IBA_INCLUDE_START) |
		((u32)0x1 << SOC_I3C_DEVICE_CTRL_I2C_SLAVE_PRESENT_START),
		adap->baseaddr + I3C_DEVICE_CTRL);

	hisi_writel(INTR_ALL, adap->baseaddr + I3C_INT_STATUS);
	hisi_writel(INTR_MASTER_MASK, adap->baseaddr + I3C_INT_STATUS_ENABLE);
	hisi_writel(INIR_ALL_MASK, adap->baseaddr + I3C_INT_SIGNAL_ENABLE);

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++) {
		if (adap->slaves[i].used == I3C_SLAVE_USED) {
			val = (adap->slaves[i].static_addr <<
			SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_STATIC_ADDR_START) |
			(adap->slaves[i].dyn_addr <<
			SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_DYN_ADDR_START);
			hisi_writel(val, adap->baseaddr + I3C_DEV_ADDR_TABLE +
				I3C_DEV_ADDR_SIZE * i);
		}
	}

	return I3C_OK;
}

static int i3c_check_bus_idle(struct i3c_adapter *adap)
{
	u32 value;
	int ret;
	int timeout = I3C_WAIT_STATUS_TIMEOUT;

	/* Make Sure Response Fifo Empty */
	do {
		hisi_readl(adap->baseaddr + I3C_CMD_RESPONSE_PORT);
		value = hisi_readl(adap->baseaddr + I3C_QUEUE_STATUS_LEVEL);
		value = (value >>
			SOC_I3C_QUEUE_STATUS_LEVEL_RESP_BUF_BLR_START) &
			I3C_BYTE_MASK;
	} while (value && timeout--);
	if (timeout <= 0) {
		HISI_PRINT_ERROR("i3c, adapt response error\n");
		return I3C_ERROR;
	}

	/* Check Command Fifo */
	value = hisi_readl(adap->baseaddr + I3C_QUEUE_STATUS_LEVEL);
	if ((value & I3C_BYTE_MASK) != I3C_CMD_FIFO_DEPTH) {
		HISI_PRINT_ERROR("i3c command left in fifo\n");
		ret = i3c_adapter_init(adap);
		if (ret < 0) {
			HISI_PRINT_ERROR(
				"i3c%u adap abnormal\n", adap->bus_num);
			return I3C_ERROR;
		}
	}

	/* Check SDA/SCL Current Level */
	value = hisi_readl(adap->baseaddr + I3C_PRESENT_STATUS);
	if ((value & I3C_2BITS_MASK) != I3C_2BITS_MASK) {
		HISI_PRINT_ERROR("i3c SDA/SCL status error 0x%x\n", value);
		ret = i3c_adapter_init(adap);
		if (ret < 0) {
			HISI_PRINT_ERROR(
				"i3c%u adap abnormal\n", adap->bus_num);
			return I3C_ERROR;
		}

		/* retry check */
		value = hisi_readl(adap->baseaddr + I3C_PRESENT_STATUS);
		if ((value & I3C_2BITS_MASK) != I3C_2BITS_MASK) {
			HISI_PRINT_ERROR(
				"i3c SDA/SCL status retry error 0x%x\n", value);
			return I3C_ERROR;
		}
	}

	return I3C_OK;
}

static int i3c_get_slave_idx(struct i3c_adapter *adapor, u8 slave)
{
	u32 i;

	if (slave == I3C_BROADCAST_CCC)
		return I3C_OK;

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++) {
		if ((adapor->slaves[i].static_addr == slave) &&
			(adapor->slaves[i].used == I3C_SLAVE_USED))
			return adapor->slaves[i].dev_idx;
	}

	return I3C_ERROR;
}

static int i3c_for_i2cdev_idx(struct i3c_adapter *adap, u8 slave)
{
	u32 val;

	val = (((u32)0x1 <<
		SOC_I3C_DEV_ADDR_TABLE_LOC1_LEGACY_I2C_DEVICE_START) |
		(slave << SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_STATIC_ADDR_START));
	hisi_writel(val, adap->baseaddr + I3C_DEV_ADDR_TABLE +
		I3C_DEV_ADDR_SIZE * I3C_SLAVE_USE_FOR_I2C_IDX);

	return I3C_SLAVE_USE_FOR_I2C_IDX;
}

static int i3c_chk_buf_write(
	struct i3c_adapter *adap, struct i3c_msg *msg, u32 *words)
{
	u32 val, i, min_len;

	val = readl(adap->baseaddr + I3C_DATA_BUFF_STATUS_LEVEL);
	if ((val & I3C_WRITE_BUF_STAT_REG_MASK) > I3C_WRITE_BUF_THRESHOLD) {
		min_len = val - I3C_WRITE_BUF_THRESHOLD;
		min_len = (*words > min_len ? min_len : *words);
		for (i = 0; i < min_len; i++) {
			hisi_writel(*(uint32_t *)msg->data,
				adap->baseaddr + I3C_DATA_PORT);
			msg->data += BYTES_OF_WORD;
		}
		*words = *words - min_len;
	}

	val = readl(adap->baseaddr + I3C_INT_STATUS);
	if (val & TRANSFER_ERR_INT_STAT_MASK)
		return I3C_ERROR;

	return I3C_OK;
}

static void i3c_dw_write(struct i3c_adapter *adap)
{
	int times = I3C_TIMEOUT_VALUE;
	struct i3c_msg *msg = NULL;
	u32 val, len, words, index;
	u8 left;

	msg = adap->msg_idx >= adap->msg_num ? NULL : &adap->msg[adap->msg_idx];
	if (!msg) {
		HISI_PRINT_ERROR("i3c%u msg_idx is invalid %d, %d\n",
			adap->bus_num, adap->msg_idx, adap->msg_num);
		return;
	}

	len = msg->len;
	words = len / BYTES_OF_WORD;
	while ((words > 0) && (times > 0)) {
		if (i3c_chk_buf_write(adap, msg, &words))
			return;
		hisi_udelay(1); /* delay 1 us */
		times--;
	}
	if (times <= 0)
		HISI_PRINT_ERROR(
			"%s, write to controller timeout!\n", __func__);

	left = len % BYTES_OF_WORD;
	if (left) {
		val = 0;
		for (index = 0; index < left; index++) {
			val |= ((*msg->data) << (index * 8)); /* 8 bit */
			msg->data++;
		}
		hisi_writel(val, adap->baseaddr + I3C_DATA_PORT);
	}

	adap->msg_idx++;
}

static int i3c_chk_buf_read(
	struct i3c_adapter *adap, struct i3c_msg *msg)
{
	u32 len, index, val;
	int words = msg->len / BYTES_OF_WORD;
	int times = I3C_TIMEOUT_VALUE;

	while ((words > 0) && (times > 0)) {
		len = hisi_readl(adap->baseaddr + I3C_DATA_BUFF_STATUS_LEVEL);
		len = I3C_BYTE_MASK &
			(len >> SOC_I3C_DATA_BUFF_STATUS_LV_RX_BUF_BLR_START);
		if (len > 0) {
			len = ((u32)words > len ? len : (u32)words);
			for (index = 0; index < len; index++) {
				*(uint32_t *)msg->data = readl(adap->baseaddr +
					I3C_DATA_PORT);
				msg->data += BYTES_OF_WORD;
			}
			words -= len;
		}

		val = readl(adap->baseaddr + I3C_INT_STATUS);
		if (val & TRANSFER_ERR_INT_STAT_MASK)
			return I3C_ERROR;

		hisi_udelay(1); /* delay 1 us */
		times--;
	}

	return I3C_OK;
}

static int i3c_chk_read_left_data(
	struct i3c_adapter *adap, struct i3c_msg *msg)
{
	u32 index, len, val;
	int times = I3C_TIMEOUT_VALUE;

	msg->len %= BYTES_OF_WORD;
	if (!msg->len)
		return I3C_OK;

	/* Get and check read buf len */
	do {
		len = hisi_readl(adap->baseaddr + I3C_DATA_BUFF_STATUS_LEVEL);
		len = I3C_BYTE_MASK &
			(len >> SOC_I3C_DATA_BUFF_STATUS_LV_RX_BUF_BLR_START);
		val = readl(adap->baseaddr + I3C_INT_STATUS);
		if (val & TRANSFER_ERR_INT_STAT_MASK)
			return I3C_ERROR;

		hisi_udelay(1); /* delay 1 us */
		times--;
	} while ((!len) && (times > 0));

	if (times <= 0) {
		HISI_PRINT_ERROR(
			"%s:read from controller timeout!\n", __func__);
		return I3C_OK;
	}

	val = hisi_readl(adap->baseaddr + I3C_DATA_PORT);
	for (index = 0; index < msg->len; index++) {
		*(msg->data) =
			(val >> (index * 8)) & I3C_BYTE_MASK; /* 8 bit */
		msg->data++;
	}
	msg->len = 0;

	return I3C_OK;
}

static void i3c_dw_read(struct i3c_adapter *adap)
{
	struct i3c_msg *msg = NULL;

	msg = adap->msg_idx >= adap->msg_num ? NULL : &adap->msg[adap->msg_idx];
	if (!msg) {
		HISI_PRINT_ERROR("i3c%u msg_idx is invalid %d, %d\n",
			adap->bus_num, adap->msg_idx, adap->msg_num);
		return;
	}

	if (!msg->len) {
		HISI_PRINT_ERROR("i3c%u read msg len is zero %d, %d\n",
			adap->bus_num, adap->msg_idx, adap->msg_num);
		return;
	}

	if (i3c_chk_buf_read(adap, msg))
		return;

	if (i3c_chk_read_left_data(adap, msg))
		return;
}

static int i3c_dw_isr(struct i3c_adapter *adap)
{
	u32 nresp;
	u32 resp;
	int ret = I3C_OK;
	u32 i;
	u32 error;

	nresp = hisi_readl(adap->baseaddr + I3C_QUEUE_STATUS_LEVEL);
	nresp = QUEUE_STATUS_LEVEL_RESP(nresp);

	for (i = 0; i < nresp; i++) {
		resp = hisi_readl(adap->baseaddr + I3C_CMD_RESPONSE_PORT);
		error = RESPONSE_PORT_ERR_STATUS(resp);
		HISI_PRINT_DEBUG("isr error irq = 0x%x\n", error);
		switch (error) {
		case RESPONSE_NO_ERROR:
			break;
		case RESPONSE_ERROR_PARITY: /* fall through */
		case RESPONSE_ERROR_IBA_NACK: /* fall through */
		case RESPONSE_ERROR_TRANSF_ABORT: /* fall through */
		case RESPONSE_ERROR_CRC: /* fall through */
		case RESPONSE_ERROR_FRAME:
			ret = -I3C_TRANS_BROAD_NACK;
			break;
		case RESPONSE_ERROR_OVER_UNDER_FLOW:
			ret = -I3C_TRANS_BUF_OVERFLOW;
			break;
		case RESPONSE_ERROR_I2C_W_NACK_ERR: /* fall through */
		case RESPONSE_ERROR_ADDRESS_NACK: /* fall through */
		default:
			ret = -I3C_TRANS_SLVADDR_NACK;
			break;
		}

		if (ret < 0) {
			HISI_PRINT_DEBUG("i3c transfer error ret = %d\n", ret);
			i3c_reset_controller(adap);
			return ret;
		}
	}

	return I3C_OK;
}

static int i3c_wait_complete(struct i3c_adapter *adap)
{
	int wait_cnt = I3C_WAIT_COMPLETE_TIMEOUT;
	u32 int_stat;
	int ret;

	do {
		int_stat = hisi_readl(adap->baseaddr + I3C_INT_STATUS);
		if (int_stat)
			break;

		hisi_udelay(I3C_WAIT_STATUS_INTERVAL);
		wait_cnt--;
		if (wait_cnt <= 0) {
			HISI_PRINT_DEBUG(
				"wait cmd resp timeout 0x%x\n", int_stat);
			return -I3C_TRANS_TIMEOUT;
		}
	} while (1);

	ret = i3c_dw_isr(adap);
	if (ret < 0)
		HISI_PRINT_DEBUG("i3c isr err %d\n", ret);

	return ret;
}

static int i3c_dw_prepare_xfer_one_msg(struct i3c_adapter *adap,
	struct i3c_msg *msg, u8 *o_dev_idx)
{
	u8 dev_idx = I3C_INVALID_DEV_IDX;

	if (!msg->data && msg->len) {
		HISI_PRINT_ERROR("%s data is null\n", __func__);
		return -I3C_TRANS_PARA_ERROR;
	}

	if (msg->mode == I3C_MODE_I3C) {
		dev_idx = i3c_get_slave_idx(adap, msg->slave);
		if (dev_idx >= I3C_SLAVE_USE_FOR_I3C_NUM) {
			HISI_PRINT_ERROR("slave 0x%x not registered\n",
				msg->slave);
			return -I3C_TRANS_SLV_NO_REGIST;
		}
	} else if (msg->mode == I3C_MODE_I2C) {
		dev_idx = i3c_for_i2cdev_idx(adap, msg->slave);
	} else {
		HISI_PRINT_ERROR("i3c mode error %d\n", msg->mode);
		return -I3C_TRANS_PARA_ERROR;
	}

	*o_dev_idx = dev_idx;

	return I3C_OK;
}

static void i3c_dw_wrcmd_for_xfer(struct i3c_adapter *adap, u8 dev_idx,
	struct i3c_msg *msg, int msg_idx, int msg_num)
{
	union i3c_command cmd;

	/* config transfer argue command */
	cmd.value = 0;
	cmd.trans_arg_cmd.cmd_attr = I3C_CMD_ATTR_TRANS_ARG;
	cmd.trans_arg_cmd.data_len = msg->len;
	hisi_writel(cmd.value, adap->baseaddr + I3C_COMMAND_PORT);

	/* config transfer command */
	cmd.value = 0;
	cmd.trans_cmd.cmd_attr = I3C_CMD_ATTR_TRANS;
	cmd.trans_cmd.tid = I3C_TRANS_TID + msg_idx;
	cmd.trans_cmd.cmd = msg->cmd;
	cmd.trans_cmd.cp = msg->cp;
	cmd.trans_cmd.dev_idx = dev_idx;
	cmd.trans_cmd.rw = msg->rw;
	cmd.trans_cmd.roc = 1;
	cmd.trans_cmd.sdap = 0;
	if (msg_idx == (msg_num - 1))
		cmd.trans_cmd.toc = 1;  /* last msg send with stop bit */
	else
		cmd.trans_cmd.toc = 0;  /* not caryy stop bit */

	hisi_writel(cmd.value, adap->baseaddr + I3C_COMMAND_PORT);
}

static int i3c_dw_xfer(struct i3c_adapter *adap, struct i3c_msg *msg,
	u8 msg_num)
{
	int ret, i;
	u8 dev_idx = I3C_INVALID_DEV_IDX;
	u32 thld_ctrl;

	ret = i3c_check_bus_idle(adap);
	if (ret < 0) {
		HISI_PRINT_ERROR(
			"i3c%u bus idle check failed\n", adap->bus_num);
		return -I3C_TRANS_BUS_BUSY;
	}

	adap->msg = msg;
	adap->msg_num = msg_num;
	adap->msg_idx = 0;

	thld_ctrl = hisi_readl(adap->baseaddr + I3C_QUEUE_THLD_CTRL);
	thld_ctrl &= ~QUEUE_THLD_CTRL_RESP_BUF_MASK;
	thld_ctrl |= QUEUE_THLD_CTRL_RESP_BUF(msg_num);
	hisi_writel(thld_ctrl, adap->baseaddr + I3C_QUEUE_THLD_CTRL);

	for (i = 0; i < msg_num; i++) {
		ret = i3c_dw_prepare_xfer_one_msg(adap, &msg[i], &dev_idx);
		if (ret)
			return ret;

		i3c_dw_wrcmd_for_xfer(adap, dev_idx, &msg[i], i, msg_num);

		if (msg[i].rw == I3C_MSG_WR)
			i3c_dw_write(adap);

		if (msg[i].rw == I3C_MSG_RD)
			i3c_dw_read(adap);
	}

	ret = i3c_wait_complete(adap);
	if (ret < 0)
		HISI_PRINT_DEBUG("i3c wait complete fail\n");

	return ret;
}

static int dw_i3c_read(struct i3c_adapter *adap, u8 slave, u32 reg,
	u8 *data, u32 len, u8 mode)
{
	struct i3c_msg msg[I3C_MAX_MSG_NUM];
	int ret;
	u32 wdata = reg;

	msg[0].slave = slave;
	msg[0].rw = I3C_MSG_WR;
	msg[0].cmd = 0;
	msg[0].cp = 0;
	msg[0].data = (u8 *)&wdata;

	/*
	 * length of slave device address is 2byte or 1byte,
	 * depending on I3C_SLVAE_REG_MAX_LEN
	 */
	msg[0].len = (reg & I3C_SLVAE_REG_MAX_LEN) ? 2 : 1;
	msg[0].mode = mode;

	msg[1].slave = slave;
	msg[1].rw = I3C_MSG_RD;
	msg[1].cmd = 0;
	msg[1].cp = 0;
	msg[1].data = data;
	msg[1].len = len;
	msg[1].mode = mode;

	ret = i3c_dw_xfer(adap, msg, I3C_MAX_MSG_NUM);

	return ret;
}

static int dw_i3c_write(struct i3c_adapter *adap, u8 slave, u32 reg,
	u8 *data, u32 len, u8 mode)
{
	struct i3c_msg msg;
	int ret;
	u8 *p = NULL;
	u32 extra_len;

	if (len > I3C_MAX_BUF_LEN) {
		HISI_PRINT_ERROR("i3c%u write, input len is too long\n",
			adap->bus_num);
		return -I3C_TRANS_PARA_ERROR;
	}

	/*
	 * length of slave device address is 2byte or 1byte,
	 * depending on I3C_SLVAE_REG_MAX_LEN
	 */
	extra_len = (reg & I3C_SLVAE_REG_MAX_LEN) ? 2 : 1;
	p = malloc(len + extra_len);
	if (!p) {
		HISI_PRINT_ERROR("i3c%u write alloc %u mem failed\n",
			adap->bus_num, len);
		return -I3C_TRANS_PARA_ERROR;
	}

	if (memcpy_s(p, extra_len + len, &reg, extra_len) != EOK) {
		HISI_PRINT_ERROR("memcpy_s to p failed\n");
		free(p);
		return -I3C_TRANS_PARA_ERROR;
	}

	if (memcpy_s(&p[extra_len], len, data, len) != EOK) {
		HISI_PRINT_ERROR("memcpy_s to p[extra_len] failed\n");
		free(p);
		return -I3C_TRANS_PARA_ERROR;
	}

	msg.slave = slave;
	msg.rw = I3C_MSG_WR;
	msg.cmd = 0;
	msg.cp = 0; /* ccc cmd invalid */
	msg.data = p;
	msg.len = len + extra_len;
	msg.mode = mode;

	ret = i3c_dw_xfer(adap, &msg, 1);

	free(p);

	return ret;
}

static int dw_i3c_block_read(struct i3c_adapter *adap, u8 slave, u8 *data,
	u16 len, u8 mode)
{
	struct i3c_msg msg;
	int ret;

	msg.slave = slave;
	msg.rw = I3C_MSG_RD;
	msg.cp = 0; /* ccc cmd invalid */
	msg.cmd = 0;
	msg.data = data;
	msg.mode = mode;
	msg.len = len;

	ret = i3c_dw_xfer(adap, &msg, 1);

	return ret;
}

static int dw_i3c_block_write(struct i3c_adapter *adap, u8 slave,
	u8 *data, u16 len, u8 mode)
{
	struct i3c_msg msg;
	int ret;
	u8 *p = NULL;

	if (len > I3C_MAX_BUF_LEN) {
		HISI_PRINT_ERROR("i3c%u write, input len is too long\n",
			adap->bus_num);
		return -I3C_TRANS_PARA_ERROR;
	}

	p = (u8 *)malloc(len);
	if (!p) {
		HISI_PRINT_ERROR("i3c%u write alloc %d mem failed\n",
			adap->bus_num, len);
		return -I3C_TRANS_PARA_ERROR;
	}

	if (memcpy_s(p, len, data, len) != EOK) {
		HISI_PRINT_ERROR("i3c%u %s:memcpy_s failed\n",
			adap->bus_num, __func__);
		free(p);
		return -I3C_TRANS_PARA_ERROR;
	}

	msg.slave = slave;
	msg.rw = I3C_MSG_WR;
	msg.cmd = 0;
	msg.cp = 0; /* ccc cmd invalid */
	msg.data = p;
	msg.len = len;
	msg.mode = mode;

	ret = i3c_dw_xfer(adap, &msg, 1);

	free(p);

	return ret;
}

static int i3c_ccc_write(struct i3c_adapter *adap, u8 slave, u8 cmd,
	u8 *data, u32 len)
{
	struct i3c_msg msg;
	int ret;

	msg.slave = slave;
	msg.rw = I3C_MSG_WR;
	msg.cmd = cmd;
	msg.cp = 1; /* ccc cmd valid */
	msg.data = data;
	msg.len = len;
	msg.mode = I3C_MODE_I3C;
	/* transfer 1 msg */
	ret = i3c_dw_xfer(adap, &msg, 1);

	return ret;
}

static int i3c_broadcast_reset_dynaddr(struct i3c_adapter *adap)
{
	u32 i;
	int ret;

	ret = i3c_ccc_write(adap, I3C_BROADCAST_CCC, BROAD_RSTDAA, NULL, 0);
	if (ret < 0) {
		HISI_PRINT_ERROR("i3c ccc write fail, ret:%d\n", ret);
		return ret;
	}

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++)
		adap->slaves[i].used = I3C_SLAVE_UNUSED;

	return I3C_OK;
}

static int hisi_i3c_get_usedfull_adap(struct i3c_adapter *adap, u32 slv_addr,
	u32 dyn_addr, int *apt_idx)
{
	int i;

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++) {
		if (adap->slaves[i].used != I3C_SLAVE_USED)
			break;

		if (adap->slaves[i].static_addr == slv_addr) {
			HISI_PRINT_ERROR(
				"set_dynaddr:slave 0x%x has been set\n",
				slv_addr);
			return -I3C_TRANS_PARA_ERROR;
		}
		if ((adap->slaves[i].dyn_addr &
			I3C_SLAVE_ADDR_MASK) == dyn_addr) {
			HISI_PRINT_ERROR(
				"set_dynaddr:dynaddr 0x%x has been used\n",
				dyn_addr);
			return -I3C_TRANS_PARA_ERROR;
		}
	}

	if (i == I3C_SLAVE_USE_FOR_I3C_NUM) {
		HISI_PRINT_ERROR("i3c%u slave num exceed\n", adap->bus_num);
		return -I3C_TRANS_PARA_ERROR;
	}

	*apt_idx = i;

	return I3C_OK;
}

static int hisi_i3c_prepare_adap_for_dynaddr(struct i3c_adapter *adap,
	struct i3c_msg *msg_tmp, u8 dev_idx, u32 slv_addr, u32 dyn_addr)
{
	adap->slaves[dev_idx].dev_idx = dev_idx;
	adap->slaves[dev_idx].used = I3C_SLAVE_USED;
	adap->slaves[dev_idx].static_addr = slv_addr;
	dyn_addr = i3c_dynaddr_add_parity(dyn_addr);
	adap->slaves[dev_idx].dyn_addr = dyn_addr;

	if (memset_s(msg_tmp, sizeof(struct i3c_msg), 0,
		sizeof(struct i3c_msg)) != EOK) {
		HISI_PRINT_ERROR("memset_s msg_tmp failed\n");
		return I3C_ERROR;
	}
	msg_tmp->len = 0;
	adap->msg = msg_tmp;
	adap->msg_num = 1;
	adap->msg_idx = 0;

	return I3C_OK;
}

static void hisi_i3c_dw_wrcmd_for_dynaddr(struct i3c_adapter *adap, u8 dev_idx)
{
	union i3c_command cmd;

	cmd.value = 0;
	cmd.addr_asgn_cmd.cmd_attr = I3C_CMD_ATTR_ADDR_ASGN;
	cmd.addr_asgn_cmd.tid = I3C_SET_DYNADDR_TID;
	cmd.addr_asgn_cmd.cmd = DIRECT_SETDASA;
	cmd.addr_asgn_cmd.dev_idx = dev_idx;
	cmd.addr_asgn_cmd.dev_cnt = 1;
	cmd.addr_asgn_cmd.toc = 1; /* caryy stop bit */
	cmd.addr_asgn_cmd.roc = 1;

	hisi_writel(cmd.value, adap->baseaddr + I3C_COMMAND_PORT);
}

static int hisi_i3c_pre_reset_dynaddr(struct i3c_adapter *adap)
{
	int ret;

	if (!adap->rst_flag) {
		ret = i3c_broadcast_reset_dynaddr(adap);
		if (ret < 0) {
			HISI_PRINT_ERROR(
				"i3c%u broadcast reset dynaddr error\n",
				adap->bus_num);
			return ret;
		}
		adap->rst_flag = 1;
	}

	return I3C_OK;
}

int hisi_i3c_set_dynaddr(u32 bus_num, u32 slv_addr, u32 dynaddr)
{
	int apt_idx = I3C_SLAVE_USE_FOR_I3C_NUM;
	u32 dyn_addr;
	int ret;
	struct i3c_msg msg_tmp;
	struct i3c_adapter *adap = NULL;

	HISI_PRINT_ERROR("set dynaddr\n");
	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("%s: adap is NULL\n", __func__);
		return I3C_ERROR;
	}

	ret = hisi_i3c_pre_reset_dynaddr(adap);
	if (ret)
		return ret;

	if (!dynaddr)
		dyn_addr = slv_addr;
	else
		dyn_addr = dynaddr;

	ret = hisi_i3c_get_usedfull_adap(adap, slv_addr, dyn_addr, &apt_idx);
	if (ret || apt_idx >= I3C_SLAVE_MAX_NUM) {
		HISI_PRINT_ERROR("i3c%u get usedfull adap fail, i:%d\n",
			adap->bus_num, apt_idx);
		return -I3C_TRANS_PARA_ERROR;
	}

	ret = hisi_i3c_prepare_adap_for_dynaddr(
		adap, &msg_tmp, apt_idx, slv_addr, dyn_addr);
	if (ret != I3C_OK) {
		HISI_PRINT_ERROR("i3c%u bus prepare adap fail\n", adap->bus_num);
		return I3C_ERROR;
	}

	ret = i3c_check_bus_idle(adap);
	if (ret < 0) {
		HISI_PRINT_ERROR("i3c%u bus idle check fail\n", adap->bus_num);
		return -I3C_TRANS_BUS_BUSY;
	}

	hisi_writel((
		slv_addr << SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_STATIC_ADDR_START) |
		(dyn_addr << SOC_I3C_DEV_ADDR_TABLE_LOC1_DEV_DYN_ADDR_START),
		(u32)(adap->baseaddr + I3C_DEV_ADDR_TABLE +
			I3C_DEV_ADDR_SIZE * apt_idx));

	hisi_i3c_dw_wrcmd_for_dynaddr(adap, apt_idx);

	ret = i3c_wait_complete(adap);
	if (ret < 0)
		HISI_PRINT_DEBUG("i3c wait complete fail\n");

	return ret;
}

int hisi_i3c_clear_software_dynaddr(u32 bus_num, u8 slv_addr)
{
	struct i3c_adapter *adap = NULL;
	u32 i;

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return I3C_ERROR;
	}

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++) {
		if (adap->slaves[i].static_addr == slv_addr) {
			adap->slaves[i].used = I3C_SLAVE_UNUSED;
			return I3C_OK;
		}
	}

	HISI_PRINT_ERROR("slave 0x%x is not exist\n", slv_addr);
	return I3C_ERROR;
}

int hisi_i3c_read(u32 bus_num, u8 slave, u32 reg, u8 *data, u32 len, u8 mode)
{
	struct i3c_adapter *adap = NULL;
	int ret;

	if (!data) {
		HISI_PRINT_ERROR("[%s]data is NULL\n", __func__);
		return I3C_ERROR;
	}

	if (!len) {
		HISI_PRINT_ERROR("[%s]len is zero\n", __func__);
		return I3C_ERROR;
	}

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return I3C_ERROR;
	}

	ret = dw_i3c_read(adap, slave, reg, data, len, mode);
	if (ret < 0)
		HISI_PRINT_ERROR("[%s]failed, err_num %d\n", __func__, ret);

	return ret;
}

int hisi_i3c_write(u32 bus_num, u8 slave, u32 reg, u8 *data, u32 len, u8 mode)
{
	struct i3c_adapter *adap = NULL;
	int ret;

	if (!data) {
		HISI_PRINT_ERROR("[%s]data is NULL\n", __func__);
		return I3C_ERROR;
	}

	if (!len) {
		HISI_PRINT_ERROR("[%s]len is zero\n", __func__);
		return I3C_ERROR;
	}

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return I3C_ERROR;
	}

	ret = dw_i3c_write(adap, slave, reg, data, len, mode);
	if (ret < 0)
		HISI_PRINT_ERROR("[%s]failed, err_num %d\n", __func__, ret);

	return ret;
}

int hisi_i3c_block_read(u8 bus_num, u8 slave, u8 *data, u16 len, u8 mode)
{
	struct i3c_adapter *adap = NULL;
	int ret;

	if (!data) {
		HISI_PRINT_ERROR("[%s]data is NULL\n", __func__);
		return I3C_ERROR;
	}

	if (!len) {
		HISI_PRINT_ERROR("[%s]len is zero\n", __func__);
		return I3C_ERROR;
	}

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return I3C_ERROR;
	}

	ret = dw_i3c_block_read(adap, slave, data, len, mode);
	if (ret < 0)
		HISI_PRINT_ERROR("[%s]failed, err_num %d\n", __func__, ret);

	return ret;
}

int hisi_i3c_block_write(u8 bus_num, u8 slave, u8 *data, u16 len, u8 mode)
{
	struct i3c_adapter *adap = NULL;
	int ret;

	if (!data) {
		HISI_PRINT_ERROR("[%s]data is NULL\n", __func__);
		return I3C_ERROR;
	}

	if (!len) {
		HISI_PRINT_ERROR("[%s]len is zero\n", __func__);
		return I3C_ERROR;
	}

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return I3C_ERROR;
	}

	ret = dw_i3c_block_write(adap, slave, data, len, mode);
	if (ret < 0)
		HISI_PRINT_ERROR("[%s]failed, err_num %d\n", __func__, ret);

	return ret;
}

void hisi_i3c_init(u32 bus_num)
{
	struct i3c_adapter *adap = NULL;
	u32 i;
	int ret;

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return;
	}

	for (i = 0; i < I3C_SLAVE_USE_FOR_I3C_NUM; i++)
		adap->slaves[i].used = I3C_SLAVE_UNUSED;

	ret = i3c_tzpc_cfg(adap, SEC_I3C);
	if (ret == I3C_ERROR) {
		HISI_PRINT_ERROR("i3c_tzpc_cfg is failed\n");
		return;
	}
	i3c_pinmux_switch(adap, I3C_IO_FUNC_I3C);
	i3c_clk_enable(adap);

	ret = i3c_adapter_init(adap);
	if (ret < 0) {
		i3c_clk_disable(adap);
		i3c_pinmux_switch(adap, I3C_IO_FUNC_NORMAL);
		ret = i3c_tzpc_cfg(adap, UNSEC_I3C);
		if (ret == I3C_ERROR)
			HISI_PRINT_ERROR("i3c_tzpc_cfg is failed\n");
		HISI_PRINT_ERROR("i3c%u adap init error\n", adap->bus_num);
		return;
	}

	adap->rst_flag = 0;
}

void hisi_i3c_exit(u32 bus_num)
{
	struct i3c_adapter *adap = NULL;
	int ret;

	adap = i3c_get_adapter(bus_num);
	if (!adap) {
		HISI_PRINT_ERROR("[%s]get i3c controller failed\n", __func__);
		return;
	}

	hisi_writel(0x0, adap->baseaddr + I3C_DEVICE_CTRL);

	i3c_clk_disable(adap);
	i3c_pinmux_switch(adap, I3C_IO_FUNC_NORMAL);

	ret = i3c_tzpc_cfg(adap, UNSEC_I3C);
	if (ret == I3C_ERROR)
		HISI_PRINT_ERROR("i3c_tzpc_cfg is failed\n");
}

