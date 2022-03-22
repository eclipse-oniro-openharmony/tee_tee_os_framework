/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP DPTX AUX DPCD Driver
 * Author: Hisilicon DSS
 * Create: 2019-07-07
 */

#include "hisi_hdcp_dp.h"

static int dptx_aux_read_data(uint8_t *bytes, uint32_t len)
{
	uint32_t i;
	uint32_t data[AUX_DATA_REG_CNT] = {0};

	if (bytes == NULL) {
		HISI_HDCP_DEBUG("bytes is null\n");
		return DPTX_RW_ERR;
	}

	data[DATA_INDEX0] = (uint32_t)hdcp_get_value(DPTX_AUX_RD_DATA0);
	data[DATA_INDEX1] = (uint32_t)hdcp_get_value(DPTX_AUX_RD_DATA1);
	data[DATA_INDEX2] = (uint32_t)hdcp_get_value(DPTX_AUX_RD_DATA2);
	data[DATA_INDEX3] = (uint32_t)hdcp_get_value(DPTX_AUX_RD_DATA3);

	for (i = 0; i < len; i++) {
		if ((i / AUX_DATA_REG_CNT) > (AUX_DATA_REG_CNT - 1))
			return DPTX_RW_ERR;

		bytes[i] = (data[i / AUX_DATA_REG_CNT] >> ((i % AUX_DATA_REG_CNT) * UINT8_WIDTH_IN_BITS)) & 0xff;
	}

	return len;
}

static int dptx_aux_write_data(uint8_t const *bytes, uint32_t len)
{
	uint32_t i;
	uint32_t data[AUX_DATA_REG_CNT] = {0};

	if (bytes == NULL) {
		HISI_HDCP_DEBUG("bytes is null\n");
		return DPTX_RW_ERR;
	}

	for (i = 0; i < len; i++) {
		if ((i / AUX_DATA_REG_CNT) > (AUX_DATA_REG_CNT - 1))
			return DPTX_RW_ERR;

		data[i / AUX_DATA_REG_CNT] |= (bytes[i] << ((i % AUX_DATA_REG_CNT) * UINT8_WIDTH_IN_BITS));
	}

	hdcp_set_reg(data[DATA_INDEX0], DPTX_AUX_WR_DATA0);
	hdcp_set_reg(data[DATA_INDEX1], DPTX_AUX_WR_DATA1);
	hdcp_set_reg(data[DATA_INDEX2], DPTX_AUX_WR_DATA2);
	hdcp_set_reg(data[DATA_INDEX3], DPTX_AUX_WR_DATA3);
	return len;
}

static void dptx_aux_clear_data(void)
{
	hdcp_set_reg(0, DPTX_AUX_WR_DATA0);
	hdcp_set_reg(0, DPTX_AUX_WR_DATA1);
	hdcp_set_reg(0, DPTX_AUX_WR_DATA2);
	hdcp_set_reg(0, DPTX_AUX_WR_DATA3);
}

static void dptx_aux_set_cmd(bool rw, uint32_t addr, uint32_t len)
{
	uint32_t type;
	uint32_t aux_cmd;

	type = rw ? DPTX_AUX_CMD_TYPE_READ : DPTX_AUX_CMD_TYPE_WRITE;
	type |= DPTX_AUX_CMD_TYPE_NATIVE;

	aux_cmd = ((type << DPTX_AUX_CMD_TYPE_SHIFT) |
		(addr << DPTX_AUX_CMD_ADDR_SHIFT) |
		((len - 1) << DPTX_AUX_CMD_REQ_LEN_SHIFT));

	hdcp_set_reg(aux_cmd, DPTX_AUX_CMD_ADDR);
}

static int dptx_aux_set_req(void)
{
	uint32_t aux_req;
	int count = 0;

	hdcp_set_reg(0x1, DPTX_AUX_REQ);
	while (1) {
		aux_req = (uint32_t)hdcp_get_value(DPTX_AUX_REQ);
		if ((aux_req & DPTX_CFG_AUX_REQ) == 0)
			break;

		count++;
		if (count > DPTX_WAIT_REPLY_CNT) {
			HISI_HDCP_DEBUG("wait aux_req=0 exceeded retries\n");
			return DPTX_RW_ERR;
		}

		udelay(1); /* wait aux reply interval */
	};

	return DPTX_RW_SUCCESS;
}

void dptx_soft_reset(uint32_t bits)
{
	uint32_t rst;

	bits &= (DPTX_RST_CTRL_ALL);
	rst = (uint32_t)hdcp_get_value(DPTX_RST_CTRL);
	rst |= bits;
	hdcp_set_reg(rst, DPTX_RST_CTRL);
}

static int dptx_aux_check_status(bool rw)
{
	uint32_t aux_status;
	uint32_t cfg_aux_status, cfg_aux_reply_err, cfg_aux_timeout;
	uint32_t valid_byte;

	aux_status = (uint32_t)hdcp_get_value(DPTX_AUX_STATUS);
	cfg_aux_status = (aux_status & DPTX_CFG_AUX_STATUS_MASK) >> DPTX_CFG_AUX_STATUS_SHIFT;
	cfg_aux_reply_err = (aux_status & DPTX_CFG_AUX_REPLY_ERR_DETECTED_MASK) >> DPTX_CFG_AUX_REPLY_ERR_DETECTED_SHIFT;
	cfg_aux_timeout = aux_status & DPTX_CFG_AUX_TIMEOUT;
	valid_byte = (aux_status & DPTX_CFG_AUX_READY_BYTE_MASK) >> DPTX_CFG_AUX_READY_BYTE_SHIFT;

	switch (cfg_aux_status) {
	case DPTX_CFG_AUX_STATUS_ACK:
		if (rw) {
			if (valid_byte <= 1) {
				HISI_HDCP_DEBUG("read bytes length error, valid_byte is %u, timeout is %u, reply_err is %u\n",
					valid_byte, cfg_aux_timeout, cfg_aux_reply_err);
				dptx_soft_reset(DPTX_AUX_RST_N);
				return DPTX_RW_RETRY;
			}
		} else {
			if (valid_byte != 1) {
				HISI_HDCP_DEBUG("write only part bytes, valid_byte is %u, timeout is %u, reply_err is %u\n",
					valid_byte, cfg_aux_timeout, cfg_aux_reply_err);
				dptx_soft_reset(DPTX_AUX_RST_N);
				return DPTX_RW_RETRY;
			}
		}
		break;
	case DPTX_CFG_AUX_STATUS_AUX_NACK:
	case DPTX_CFG_AUX_STATUS_I2C_NACK:
		HISI_HDCP_DEBUG("AUX Nack\n");
		return DPTX_RW_ERR;
	case DPTX_CFG_AUX_STATUS_AUX_DEFER:
	case DPTX_CFG_AUX_STATUS_I2C_DEFER:
		HISI_HDCP_DEBUG("AUX Defer\n");
		return DPTX_RW_RETRY;
	default:
		HISI_HDCP_DEBUG("AUX Status Invalid\n");
		dptx_soft_reset(DPTX_AUX_RST_N);
		return DPTX_RW_RETRY;
	}
	return DPTX_RW_SUCCESS;
}

static int dptx_aux_rw(bool rw, bool i2c, uint32_t addr, uint8_t *bytes, uint32_t len)
{
	int tries = 0;
	int ret;
	(void)i2c;
	if (bytes == NULL) {
		HISI_HDCP_DEBUG("bytes is null\n");
		return -DPTX_RW_ERR;
	}

again:
	udelay(DPTX_RW_WAIT_CNT);
	tries++;
	if (tries > DPTX_RW_RETRY_CNT) {
		HISI_HDCP_DEBUG("AUX exceeded retries\n");
		return DPTX_RW_ERR;
	}

	if ((len > DPCD_READ_CNT) || (len == 0)) {
		HISI_HDCP_DEBUG("AUX read/write len must be 1-15, len=%d\n", len);
		return DPTX_RW_ERR;
	}

	dptx_aux_clear_data();

	if (!rw)
		dptx_aux_write_data(bytes, len);

	dptx_aux_set_cmd(rw, addr, len);
	if (dptx_aux_set_req() != DPTX_RW_SUCCESS)
		return DPTX_RW_ERR;

	ret = dptx_aux_check_status(rw);
	if (ret == DPTX_RW_ERR)
		return DPTX_RW_ERR;
	else if (ret == DPTX_RW_RETRY)
		goto again;

	if (rw)
		dptx_aux_read_data(bytes, len);

	return DPTX_RW_SUCCESS;
}

static int dptx_aux_rw_bytes(bool rw, bool i2c, uint32_t addr, uint8_t *bytes, uint32_t len)
{
	int ret = 0;
	uint32_t i;

	for (i = 0; i < len;) {
		uint32_t curlen = MinT((uint32_t)(len - i), (uint32_t)(DPCD_READ_CNT));

		ret = dptx_aux_rw(rw, i2c, addr + i, &bytes[i], curlen);
		if (ret)
			return ret;

		i += curlen;
	}
	return ret;
}

int dptx_read_bytes_from_dpcd(uint32_t regAddr, uint8_t *bytes, uint32_t len)
{
	HISI_HDCP_DEBUG("enter hdcp dpcd read, reg_addr = 0x%x\n", regAddr);

	return dptx_aux_rw_bytes(true, false, regAddr, bytes, len);
}

int dptx_write_bytes_to_dpcd(uint32_t regAddr, uint8_t *bytes, uint32_t len)
{
	HISI_HDCP_DEBUG("enter hdcp dpcd write, reg_addr = 0x%x\n", regAddr);

	return dptx_aux_rw_bytes(false, false, regAddr, bytes, len);
}


