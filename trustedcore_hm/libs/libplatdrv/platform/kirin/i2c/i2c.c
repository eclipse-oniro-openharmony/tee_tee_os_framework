
/* I2C adapter driver & I2C device interface */

#include "i2c_resource.h"
#include <hisi_boot.h>
#include <hisi_debug.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

/* register list */
#define I2C_CON 0x000
#define I2C_TAR 0x004
#define I2C_DATA_CMD 0x010
#define I2C_SS_SCL_HCNT 0x014
#define I2C_SS_SCL_LCNT 0x018
#define I2C_FS_SCL_HCNT 0x01C
#define I2C_FS_SCL_LCNT 0x020
#define I2C_INTR_MASK 0x030
#define I2C_RAW_INTR_STAT 0x034
#define I2C_RX_TL 0x038
#define I2C_TX_TL 0x03C
#define I2C_CLR_INTR 0x040
#define I2C_CLR_GEN_CALL 0x068
#define I2C_ENABLE 0x06C
#define I2C_STATUS 0x070
#define I2C_RXFLR 0x078
#define I2C_REG_HOLD_TIME 0x07C

/* regs mask */
#define I2C_TAR_MASK 0x3FF
#define I2C_STATUS_ACTIVITY 0x1

#define I2C_SLAVE_DISABLE (1 << 6)
#define I2C_RESTART_EN (1 << 5)
#define I2C_10BITS_ADDR (1 << 4)
#define I2C_MASTER_MODE (1 << 0)
#define I2C_TEST_10BIT_ADDR(x) (((x) >> 7) & 0x7)

/* i2c intr mask reg */

#define I2C_STOP_DET_MASK (1 << 9)

#define I2C_DISABLE_INTR_MASK (0 << 0)

#define I2C_IRQ_STOP_MASK 0x200

#define I2C_RESET_CONTROLLER_TIMEOUT 10

#define READ_I2C_RXFLR_RETRY_COUNT 200000
#define CHECK_STATUS_RETRY_TIMES 200

#define I2C_ENABLE_DISABLE_VALUE 0
#define I2C_ENABLE_ENABLE_VALUE 1

#define I2C_RX_TL_INIT_VALUE 0
#define I2C_TX_TL_INIT_VALUE 0x3F

/* i2c return value */
#define I2C_OK 0
#define I2C_FAIL 1

#define I2C_TZPC_ENABLE TZPC_SEC
#define I2C_TZPC_DISABLE TZPC_UNSEC

#define I2C_RETRY_NUM 3

#define I2C_S_SCL_LCNT	500000
#define I2C_1M_CLK	1000000

#define I2C_DATA_CMD_CMD	(1 << 8)
#define I2C_DATA_CMD_STOP	(1 << 9)

#define I2C_RXFLR_DATA_MASK	0x3F


/**
 * get the hardware resource by base address
 */
static struct i2c_resource *get_i2c_resource_info(const u32 chip_addr)
{
	u32 max, i;

	max = sizeof(i2c_res) / sizeof(struct i2c_resource);

	for (i = 0; i < max; i++)
		if (i2c_res[i].base == chip_addr) {
			HISI_PRINT_DEBUG(
				"i2c bus num is %d.\n", i2c_res[i].bus_id);
			return &i2c_res[i];
		}

	HISI_PRINT_ERROR("no i2c resource, base is 0x%x\n", chip_addr);
	return NULL;
}

/**
 * notes!!! this function must be called when controller belongs to the IOMCU
 * subsystem
 */
static int set_i2c_tzpc_iomcu_domain(struct i2c_resource *ir, u32 value)
{
	u32 data;

	data = hisi_readl(
		ir->tzpc_data.tzpc_info.addr + ir->tzpc_data.tzpc_info.offset);

	if (value == I2C_TZPC_ENABLE)
		data &= ~(1 << ir->tzpc_data.tzpc_info.mask_bit);
	else
		data |= 1 << ir->tzpc_data.tzpc_info.mask_bit;

	hisi_writel(
		data, ir->tzpc_data.tzpc_info.addr +
			      ir->tzpc_data.tzpc_info.offset);

	HISI_PRINT_DEBUG("i2c-%d set tzpc succ\n", ir->bus_id);

	return I2C_OK;
}

static inline int set_i2c_tzpc_ap_domain(struct i2c_resource *ir, u32 value)
{
	return tzpc_cfg(ir->tzpc_data.tzpc_map.tzpc_idx, value);
}

static int set_i2c_sec(struct i2c_resource *ir, u32 value)
{
	int ret;

	if (ir->tzpc_flag == I2C_NO_NEED_SWITCH_SEC_FLAG) {
		HISI_PRINT_DEBUG(
			"i2c-%d, no need to set sec property\n", ir->bus_id);
		return I2C_OK;
	}

	switch (ir->domain) {
	case I2C_AP_DOMAIN:
		ret = set_i2c_tzpc_ap_domain(ir, value);
		break;
	case I2C_IOMCU_DOMAIN:
		ret = set_i2c_tzpc_iomcu_domain(ir, value);
		break;
	default:
		HISI_PRINT_ERROR("i2c-%d, pelse check domain[%d]\n", ir->bus_id,
			ir->domain);
		ret = -I2C_FAIL;
		break;
	}

	return ret;
}

/* get clock rate of controller, kHz */
static inline u32 get_i2c_clk_rate(struct i2c_resource *ir)
{
	HISI_PRINT_DEBUG(
		"i2c-%d clk rate is %d kHz\n", ir->bus_id, ir->clk_rate);
	return ir->clk_rate;
}

/* i2c delay */
static void dwc_i2c_delay(int time)
{
	hisi_udelay(time);
}

static u32 dwc_i2c_scl_hcnt(
	u32 ic_clk, u32 tSYMBOL, u32 tf, int cond, int offset)
{
	if (cond)
		return ((ic_clk * tSYMBOL + I2C_S_SCL_LCNT) / I2C_1M_CLK - 8) +
			(u32)offset;
	else
		return ((ic_clk * (tSYMBOL + tf) + I2C_S_SCL_LCNT) /
			I2C_1M_CLK - 3) + (u32)offset;
}

static u32 dwc_i2c_scl_lcnt(u32 ic_clk, u32 tLOW, u32 tf, int offset)
{

	return (((ic_clk * (tLOW + tf) + I2C_S_SCL_LCNT) / I2C_1M_CLK) - 1) +
		(u32)offset;
}

/* called it when bus is abnormal. */
static void dwc_i2c_reset_controller(struct i2c_resource *ir)
{
	u32 stat;
	u32 timeout = I2C_RESET_CONTROLLER_TIMEOUT;

	hisi_writel(ir->reset_data.bit, ir->reset_data.enable);
	stat = hisi_readl(ir->reset_data.status) &
	       ir->reset_data.bit;

	while (!stat && timeout) {
		dwc_i2c_delay(1);
		stat = hisi_readl(ir->reset_data.status) &
		       ir->reset_data.bit;
		timeout--;
	}
	if (!stat && !timeout) {
		HISI_PRINT_ERROR("i2c-%d  reset: enable failed(s=%d, t=%d).\n",
			ir->bus_id, stat, timeout);
	}

	dwc_i2c_delay(1);
	timeout = I2C_RESET_CONTROLLER_TIMEOUT;
	hisi_writel(ir->reset_data.bit, ir->reset_data.disable);
	stat = hisi_readl(ir->reset_data.status) &
	       ir->reset_data.bit;

	while (stat && timeout) {
		dwc_i2c_delay(1);
		stat = hisi_readl(ir->reset_data.status) &
		       ir->reset_data.bit;
		timeout--;
	}
	if (stat && !timeout) {
		HISI_PRINT_ERROR("i2c-%d reset: disable failed(s=%d, t=%d).\n",
			ir->bus_id, stat, timeout);
	}
}

static int dwc_i2c_wait_send_complete(struct i2c_resource *ir)
{
	u32 i = 0;

	while ((!(I2C_IRQ_STOP_MASK &
		       hisi_readl(ir->base + I2C_RAW_INTR_STAT))) &&
		(i < READ_I2C_RXFLR_RETRY_COUNT)) {
		dwc_i2c_delay(5);
		i++;
	}

	dwc_i2c_delay(1000);
	if (i == READ_I2C_RXFLR_RETRY_COUNT) {
		HISI_PRINT_ERROR("i2c-%d : send time out !\n", ir->bus_id);
		return -I2C_FAIL;
	}

	return I2C_OK;
}

static int dwc_i2c_receive(struct i2c_resource *ir, u8 *buf, u32 flag)
{
	u32 i = 0;

	if (flag == 0)
		hisi_writel(I2C_DATA_CMD_CMD, ir->base + I2C_DATA_CMD);
	else
		hisi_writel(I2C_DATA_CMD_CMD | I2C_DATA_CMD_STOP,
			ir->base + I2C_DATA_CMD);

	if (flag == 0) {
		while ((!(hisi_readl(ir->base + I2C_RXFLR) &
			 I2C_RXFLR_DATA_MASK)) &&
			 (i < READ_I2C_RXFLR_RETRY_COUNT)) {
			dwc_i2c_delay(5);
			i++;
		}
	} else {
		while ((!(hisi_readl(ir->base + I2C_RAW_INTR_STAT) &
			 I2C_STOP_DET_MASK)) &&
			(i < READ_I2C_RXFLR_RETRY_COUNT)) {
			dwc_i2c_delay(5);
			i++;
		}
	}

	if (i == READ_I2C_RXFLR_RETRY_COUNT) {
		HISI_PRINT_ERROR("i2c-%d : receive time out !!!\n", ir->bus_id);
		return -I2C_FAIL;
	}

	*buf = (u8)hisi_readl(ir->base + I2C_DATA_CMD);

	return I2C_OK;
}

static int dwc_i2c_send(
	struct i2c_resource *ir, const u8 *buf, u32 len, u8 flag)
{
	u32 i;

	for (i = 0; i < len; i++) {
		if (i == len - 1 && flag == 1)
			hisi_writel(buf[i] | I2C_DATA_CMD_STOP,
				ir->base + I2C_DATA_CMD);
		else
			hisi_writel(buf[i], ir->base + I2C_DATA_CMD);
	}

	return I2C_OK;
}

static s32 dwc_i2c_check_status(struct i2c_resource *ir)
{
	u32 activity;
	u32 i;

	/* set timeout for 1ms */
	for (i = 0; i < CHECK_STATUS_RETRY_TIMES; i++) {
		activity =
			hisi_readl(ir->base + I2C_STATUS) & I2C_STATUS_ACTIVITY;
		if (activity == 0)
			return I2C_OK;

		dwc_i2c_delay(100);
	}

	return -I2C_FAIL;
}

static int dwc_i2c_init(struct i2c_resource *ir, u32 slave_addr)
{
	u16 i;
	u16 reg_value = 0;
	u32 hcnt, lcnt, input_clock_khz, sda_hold_time;

	input_clock_khz = get_i2c_clk_rate(ir);

	hisi_writel(I2C_ENABLE_DISABLE_VALUE, ir->base + I2C_ENABLE);

	hisi_writel(I2C_RX_TL_INIT_VALUE, ir->base + I2C_RX_TL);
	hisi_writel(I2C_TX_TL_INIT_VALUE, ir->base + I2C_TX_TL);

	if (ir->speed_mode == I2C_STD_SPEED) {
		hcnt = dwc_i2c_scl_hcnt(input_clock_khz,
			4000, /* STA = tHIGH = 4.0 us */
			300, 0, 0);/* 0: DW default, 1: Idea, No offsetl */
		lcnt = dwc_i2c_scl_lcnt(input_clock_khz,
			4700, 300, 0); /* tLOW = 4.7 us, No offset */
		hisi_writel(hcnt, ir->base + I2C_SS_SCL_HCNT);
		hisi_writel(lcnt, ir->base + I2C_SS_SCL_LCNT);
		HISI_PRINT_DEBUG("i2c-%d Standard-mode HCNT:LCNT = %d:%d\n",
			ir->bus_id, hcnt, lcnt);
	} else if (ir->speed_mode == I2C_FAST_SPEED) {
		hcnt = dwc_i2c_scl_hcnt(input_clock_khz,
			600,    /* STA = tHIGH = 0.6 us */
			300, 0, /* 0: DW default, 1: Ideal */
			0);     /* No offset */
		lcnt = dwc_i2c_scl_lcnt(input_clock_khz,
			1300,    /* tLOW = 1.3 us */
			300, 0); /* No offset */
		hisi_writel(hcnt, ir->base + I2C_FS_SCL_HCNT);
		hisi_writel(lcnt, ir->base + I2C_FS_SCL_LCNT);
		HISI_PRINT_DEBUG("i2c-%d Fast-mode HCNT:LCNT = %d:%d\n",
			ir->bus_id, hcnt, lcnt);
	} else {
		HISI_PRINT_ERROR("i2c-%d speed mode is error\n", ir->bus_id);
		return -I2C_FAIL;
	}

	/* hold time is 300ns */
	sda_hold_time = (input_clock_khz * 300) / I2C_1M_CLK;
	hisi_writel(sda_hold_time, ir->base + I2C_REG_HOLD_TIME);

	/* set slave addr */
	if (I2C_TEST_10BIT_ADDR(slave_addr))
		reg_value |= I2C_10BITS_ADDR;
	else
		reg_value &= ~I2C_10BITS_ADDR;

	reg_value |= (u16)ir->speed_mode | I2C_MASTER_MODE;
	reg_value |= (u16)I2C_RESTART_EN | I2C_SLAVE_DISABLE;
	hisi_writel(reg_value, ir->base + I2C_CON);

	/* set i2c slave address*/
	reg_value = slave_addr & I2C_TAR_MASK;
	hisi_writel(reg_value, ir->base + I2C_TAR);

	/* clear irq, 4 is addr wide */
	for (i = I2C_CLR_INTR; i <= I2C_CLR_GEN_CALL; i += 4)
		(void)hisi_readl(ir->base + i);

	/* enable irq mask bit */
	hisi_writel(I2C_DISABLE_INTR_MASK, ir->base + I2C_INTR_MASK);

	/* enable i2c */
	hisi_writel(I2C_ENABLE_ENABLE_VALUE, ir->base + I2C_ENABLE);

	return I2C_OK;
}

static s32 i2c_read(struct i2c_resource *ir, u8 *buf, u32 len)
{
	u32 i;
	u8 offset_addr = buf[0];
	u8 stop_flag = 0;

	if (dwc_i2c_check_status(ir)) {
		HISI_PRINT_ERROR("i2c-%d read: i2c bus busy\n",
			ir->bus_id);
		return -I2C_FAIL;
	}

	if (dwc_i2c_send(ir, &offset_addr, 1, stop_flag))
		return -I2C_FAIL;

	for (i = 0; i < len; i++) {
		if (i == len - 1) {
			if (dwc_i2c_receive(ir, buf, 1))
				return -I2C_FAIL;
		} else {
			if (dwc_i2c_receive(ir, buf, 0))
				return -I2C_FAIL;
		}
		buf++;
	}
	return I2C_OK;
}

static s32 i2c_read_reg16(struct i2c_resource *ir, u8 *buf, u32 len)
{
	u32 i;

	/*max read 64 byte*/
	if (len >= 64) {
		HISI_PRINT_ERROR("i2c-%d read_reg16 error\n", ir->bus_id);
		return -I2C_FAIL;
	}

	if (dwc_i2c_check_status(ir)) {
		HISI_PRINT_ERROR("i2c-%d read_reg16: bus busy\n",
			ir->bus_id);
		return -I2C_FAIL;
	}

	hisi_writel(buf[0], ir->base + I2C_DATA_CMD);
	hisi_writel(buf[1], ir->base + I2C_DATA_CMD);

	for (i = 0; i < len; i++) {
		if (i == len - 1)
			hisi_writel(I2C_DATA_CMD_CMD | I2C_DATA_CMD_STOP,
				ir->base + I2C_DATA_CMD);
		else
			hisi_writel(I2C_DATA_CMD_CMD, ir->base + I2C_DATA_CMD);
	}

	i = 0;
	while ((len != (hisi_readl(ir->base + I2C_RXFLR) &
		I2C_RXFLR_DATA_MASK)) &&
		(i < READ_I2C_RXFLR_RETRY_COUNT)) {
		dwc_i2c_delay(3000);
		i++;
	}

	if (i == READ_I2C_RXFLR_RETRY_COUNT) {
		HISI_PRINT_ERROR("i2c-%d  %s time out !!!\n",
			ir->bus_id, __func__);
		return -I2C_FAIL;
	}

	for (i = 0; i < len; i++) {
		*buf = hisi_readl(ir->base + I2C_DATA_CMD);
		buf++;
	}

	return I2C_OK;
}

static int i2c_write(struct i2c_resource *ir, const u8 *buf, u32 len)
{
	u8 stop_flag = 1;

	if (dwc_i2c_check_status(ir)) {
		HISI_PRINT_ERROR("i2c-%d write: i2c bus busy\n",
			ir->bus_id);
		return -I2C_FAIL;
	}

	dwc_i2c_send(ir, buf, len, stop_flag);

	return dwc_i2c_wait_send_complete(ir);
}

int hisi_i2c_read(const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr)
{
	int retry = I2C_RETRY_NUM;
	u8 offset_addr;
	int ret;
	struct i2c_resource *ir = NULL;

	ir = get_i2c_resource_info(chip_addr);
	if (ir == NULL)
		return -I2C_FAIL;

	if (buf == NULL)
		return -I2C_FAIL;

	offset_addr = buf[0];

	HISI_PRINT_DEBUG("i2c-%d %s\n", ir->bus_id, __func__);

	ret = set_i2c_sec(ir, I2C_TZPC_ENABLE);
	if (ret)
		return -I2C_FAIL;

	dwc_i2c_init(ir, slave_addr);
	while (i2c_read(ir, buf, len) && (--retry)) {
		buf[0] = offset_addr;
		hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
		dwc_i2c_reset_controller(ir);
		dwc_i2c_init(ir, slave_addr);
	}

	if (!retry)
		HISI_PRINT_ERROR("i2c-%d %s failure!\n",
			ir->bus_id, __func__);

	hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
	ret = set_i2c_sec(ir, I2C_TZPC_DISABLE);

	if (!retry || ret)
		return -I2C_FAIL;

	return I2C_OK;
}

int hisi_i2c_read_reg16(
	const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr)
{
	int retry = I2C_RETRY_NUM;
	u8 offset_addr;
	int ret;
	struct i2c_resource *ir = NULL;

	ir = get_i2c_resource_info(chip_addr);
	if (ir == NULL)
		return -I2C_FAIL;

	if (buf == NULL)
		return -I2C_FAIL;

	offset_addr = buf[0];

	HISI_PRINT_DEBUG("i2c-%d %s\n", ir->bus_id, __func__);

	ret = set_i2c_sec(ir, I2C_TZPC_ENABLE);
	if (ret)
		return -I2C_FAIL;

	dwc_i2c_init(ir, slave_addr);
	while (i2c_read_reg16(ir, buf, len) && (--retry)) {
		buf[0] = offset_addr;
		hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
		dwc_i2c_reset_controller(ir);
		dwc_i2c_init(ir, slave_addr);
	}

	if (!retry)
		HISI_PRINT_ERROR("i2c-%d %s failure!\n",
			ir->bus_id, __func__);

	hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
	ret = set_i2c_sec(ir, I2C_TZPC_DISABLE);

	if (!retry || ret)
		return -I2C_FAIL;

	return I2C_OK;
}

int hisi_i2c_write(const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr)
{
	int retry = I2C_RETRY_NUM;
	int ret;
	struct i2c_resource *ir = NULL;

	ir = get_i2c_resource_info(chip_addr);
	if (ir == NULL)
		return -I2C_FAIL;

	if (buf == NULL)
		return -I2C_FAIL;

	HISI_PRINT_DEBUG("i2c-%d %s\n", ir->bus_id, __func__);

	ret = set_i2c_sec(ir, I2C_TZPC_ENABLE);
	if (ret)
		return -I2C_FAIL;

	dwc_i2c_init(ir, slave_addr);
	while (i2c_write(ir, buf, len) && (--retry)) {
		hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
		dwc_i2c_reset_controller(ir);
		dwc_i2c_init(ir, slave_addr);
	}

	if (!retry)
		HISI_PRINT_ERROR("i2c-%d %s failure!\n",
			ir->bus_id, __func__);

	hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
	ret = set_i2c_sec(ir, I2C_TZPC_DISABLE);

	if (!retry || ret)
		return -I2C_FAIL;

	return I2C_OK;
}

/*
 *
 * Called by hisi_i2c_read_directly()
 *
 * This function directly read the IC data without
 * first writing to the register address.
 * distinguishing from i2c_read() and i2c_read_reg16().
 */
static s32 i2c_read_directly(struct i2c_resource *ir, u8 *buf, u32 len)
{
	u32 i;
	int ret;

	ret = dwc_i2c_check_status(ir);
	if (ret) {
		HISI_PRINT_ERROR("i2c-%d read: i2c bus busy\n",
			ir->bus_id);
		return -I2C_FAIL;
	}

	for (i = 0; i < len; i++) {
		if (i == len - 1) {
			ret = dwc_i2c_receive(ir, buf, 1); /* read 1 byte */
			if (ret != 0)
				return -I2C_FAIL;
		} else {
			ret = dwc_i2c_receive(ir, buf, 0);
			if (ret != 0)
				return -I2C_FAIL;
		}
		buf++;
	}
	return I2C_OK;
}

/*
 *
 * Called by i2c read functions of some i2c devices, such as TP, etc
 *
 * This function directly read data by calling the i2c_read_directly
 * function without writing to the register address.
 * distinguishing from hisi_i2c_read() and hisi_i2c_read_reg16().
 */
int hisi_i2c_read_directly(
	const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr)
{
	int retry = I2C_RETRY_NUM;
	int ret;
	struct i2c_resource *ir = NULL;

	ir = get_i2c_resource_info(chip_addr);
	if (ir == NULL)
		return -I2C_FAIL;

	if (buf == NULL)
		return -I2C_FAIL;

	HISI_PRINT_DEBUG("i2c-%d hisi_i2c_read\n", ir->bus_id);

	ret = set_i2c_sec(ir, I2C_TZPC_ENABLE);
	if (ret)
		return -I2C_FAIL;

	(void)dwc_i2c_init(ir, slave_addr);
	ret = i2c_read_directly(ir, buf, len);
	while (ret && retry) {
		hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
		dwc_i2c_reset_controller(ir);
		(void)dwc_i2c_init(ir, slave_addr);
		ret = i2c_read_directly(ir, buf, len);
		--retry;
	}

	if (!retry)
		HISI_PRINT_ERROR("i2c-%d hisi_i2c_read failure!\n",
			ir->bus_id);

	hisi_writel(I2C_ENABLE_DISABLE_VALUE, chip_addr + I2C_ENABLE);
	ret = set_i2c_sec(ir, I2C_TZPC_DISABLE);
	if (!retry || ret)
		return -I2C_FAIL;

	return I2C_OK;
}
