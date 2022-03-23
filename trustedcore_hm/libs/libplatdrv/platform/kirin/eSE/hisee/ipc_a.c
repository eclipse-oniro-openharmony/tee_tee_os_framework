/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos to hisee ipc driver.
 * Create: 2019/9/30
 */

#include "ipc_a.h"
#include "register_ops.h"
#include "ipc_msg.h"
#include "securec.h"
#include "tee_log.h" /* uart_printf_func */

#define IPC_TRUE               1
#define IPC_FALSE              0
#define IPC_WAIT_IDLE_TIMES    100
#define IPC_WAIT_SET_TIMES     5

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static unsigned short crc16(unsigned char *buffer, unsigned int len)
{
	/* the default crc_reg value must be zero.
	 * becaue this is also used in other gits.
	 */
	unsigned short crc_reg = 0;
#ifdef CONFIG_ENABLE_HISEE_CRC16
	int i, j;
	unsigned char  index;
	unsigned short to_xor;

	for (i = 0; i < len; i++) {
		index = (crc_reg ^ buffer[i]) & 0xff;
		to_xor = index;
		for (j = 0; j < 8; j++) { /* 8: 8bit for crc algorithm rule */
			if (to_xor & 0x0001) /* 0x0001: crc algorithm rule */
				to_xor = (to_xor >> 1) ^ 0x8408; /* 0x8408: crc algorithm rule */
			else
				to_xor >>= 1;
		}
		crc_reg = (crc_reg >> 8) ^ to_xor; /* 8: 8bit for crc algorithm rule */
	}
#endif
	return crc_reg;
}
#pragma GCC diagnostic pop

/* find mailbox sram block size by Memory block allocation information */
unsigned int mbx_sram_size_get(unsigned char mbx_id)
{
    unsigned int i;
    unsigned int mbx_num = 0;
    unsigned int result;

    enum block_id block_id = MAX_MBOX_FLAG;

    switch (mbx_id) {
    case IPC_INSE_FASTMBOX:
        block_id = MBOX_HISEE_TEE;
        break;
    case IPC_TEE_FASTMBOX:
        block_id = MBOX_HISEE_TEE;
        break;
    default:
        return IM_PARA_ERR;
    }

    for (i = 0; i < MAILBOX_SRAM_BLOCK; i++) {
        if (block_id == *(unsigned char *)(uintptr_t)(MAILBOX_SRAM_TABLE_ADDR + i))
            mbx_num++;
    }
    /* if used the last block need remove 32byte */
    if (block_id == *(unsigned char *)(uintptr_t)(MAILBOX_SRAM_TABLE_ADDR + MAILBOX_SRAM_BLOCK - 1))
        result = ((mbx_num * MAILBOX_SRAM_BLOCK_SIZE) - MAILBOX_SRAM_BLOCK);
    else
        result = (mbx_num * MAILBOX_SRAM_BLOCK_SIZE);

    return result;
}

/* find mailbox sram block size by Memory block allocation information */
char *mbx_sram_addr_get(unsigned char mbx_id)
{
    unsigned int i;
    char *dst = NULL;
    enum block_id block_id;

    switch (mbx_id) {
    case IPC_INSE_FASTMBOX:
        block_id = MBOX_HISEE_TEE;
        break;
    case IPC_TEE_FASTMBOX:
        block_id = MBOX_HISEE_TEE;
        break;
    default:
        return NULL;
    }

    for (i = 0; i < MAILBOX_SRAM_BLOCK; i++) {
        if (block_id == *(unsigned char *)(uintptr_t)(MAILBOX_SRAM_TABLE_ADDR + i)) {
            dst = (char *)(uintptr_t)(HISEE_MBOX_BASE_ADDR + i * MAILBOX_SRAM_BLOCK_SIZE);
            break;
        }
    }
    return dst;
}

/*
 * wait receiving of ipc-ack then release this mailbox
 * mbox_id id of mailbox channel
 * IM_OK if success  or  return IM_TIMEOUT_ERR
 */
int ipc_wait_idle(unsigned char mbox_id)
{
	unsigned int base;
	unsigned int timeout;
	unsigned int i;
	unsigned int readl_temp;
	unsigned int b_released;

	base = HISEE_IPC_BASE_ADDR;
	/* wait mailbox idle */
	timeout = IPC_WAIT_IDLE_TIMES;
	b_released = IPC_FALSE;

	readl_temp = read32(SOC_IPC_MBX_MODE_ADDR(base, mbox_id));

	while (readl_temp != IPC_STATE_IDLE && timeout != 0) {
		if ((readl_temp & IPC_STATE_MASK) == IPC_STATE_ACK && b_released == IPC_FALSE) {
			/* clear irq */
			write32(SOC_IPC_MBX_ICLR_ADDR(base, mbox_id), BIT(AP_SOURCE));
			/* release mailbox */
			write32(SOC_IPC_MBX_SOURCE_ADDR(base, mbox_id), BIT(AP_SOURCE));

			b_released = IPC_TRUE;
		}
		IPC_SLEEP(1);
		readl_temp = read32(SOC_IPC_MBX_MODE_ADDR(base, mbox_id));
		timeout--;
	}

	if (timeout == 0) {
		uart_printf_func("mbox-%d waitIdleOT:\n", mbox_id);
		uart_printf_func("[IPCMBXSOURCE]:%x\n", read32(SOC_IPC_MBX_SOURCE_ADDR(base, mbox_id)));
		uart_printf_func("[IPCMBXDSTATUS]:%x\n", read32(SOC_IPC_MBX_DSTATUS_ADDR(base, mbox_id)));
		uart_printf_func("[IPCMBXMODE]:%x\n", read32(SOC_IPC_MBX_MODE_ADDR(base, mbox_id)));
		for (i = 0; i < MAX_MAIL_SIZE; i++)
			uart_printf_func("[IPCMBXDATA%d]:%x\n", i,
					 read32(SOC_IPC_MBX_DATA0_ADDR(base, mbox_id) + i * sizeof(unsigned int)));
		return IM_TIMEOUT_ERR;
	}
	return IM_OK;
}

/*
 * send ipc_msg to mailbox
 * cfg: data of ipc_msg
 * IM_OK: success, IM_TIMEOUT_ERR: fail
 */
int ipc_send_msg(const struct ipc_msg *cfg)
{
	unsigned int timeout, base, source, cnt, mailbox_size;
	unsigned char i, mailbox;
	char *mbx_sram_addr = NULL;
	unsigned short crc_result = 0;

	if (!cfg)
		return IM_PARA_ERR;

	mailbox = cfg->mailbox_id;
	base = HISEE_IPC_BASE_ADDR;
	source = BIT(AP_SOURCE);

	/*
	 * check user data size with in mailbox sram size£¬
	 * if no data to transmit No need to judge whether to allocate mailbox sram
	 */
	mailbox_size = mbx_sram_size_get(mailbox);
	if ((cfg->mailbox_size > 0) && (cfg->mailbox_size > mailbox_size)) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_CONFLICT_ERR;
	}
	write32(SOC_IPC_LOCK_ADDR(base), REG_UNLOCK_KEY);

	if (ipc_wait_idle(mailbox) != IM_OK)
		return IM_TIMEOUT_ERR;

	/* request use mailbox */
	if (read32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox)) == 0)
		write32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox), source);
	timeout = IPC_WAIT_SET_TIMES;
	while (read32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox)) != source && timeout != 0) {
		if (read32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox)) == 0)
			write32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox), source);
		IPC_SLEEP(1);
		timeout--;
	}
	if (timeout == 0) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_TIMEOUT_ERR;
	}

	/* set irq mask */
	write32(SOC_IPC_MBX_IMASK_ADDR(base, mailbox), ~(source | cfg->dest_id));

	/* set mailbox workmode */
	write32(SOC_IPC_MBX_MODE_ADDR(base, mailbox), (cfg->mode & MBOX_MODE_MASK));

	/* set mailbox reg data */
	for (i = 0; i < MAX_MAIL_SIZE; i++)
		write32((SOC_IPC_MBX_DATA0_ADDR(base, mailbox) + i * sizeof(unsigned int)), cfg->data[i]);

	mbx_sram_addr = mbx_sram_addr_get(mailbox);
	/*
	 * set mailbox sram data
	 * copy user data to mailbox sram balock, It is possible that
	 * the data of the engine has been moved to mailbox sram. so we need to check
	 * Is it equal the data addr and the mailbox sram addr
	 */
	if (cfg->mailbox_size != 0 && cfg->mailbox_addr != 0) {
		if ((mbx_sram_addr != NULL) && (mbx_sram_addr != (char *)(uintptr_t)cfg->mailbox_addr)) {
			/* CCI constaint. Cannot use LDM/STM instructions to access SRAM */
			for (cnt = 0; cnt < cfg->mailbox_size; cnt++)
				*((char *)mbx_sram_addr + cnt) = *((char *)(uintptr_t)cfg->mailbox_addr + cnt);
		} else {
			uart_printf_func("Mbx_sram_addr:%x null or mbox data had been putted in!!!\n", mbx_sram_addr);
		}

		/* crc16 check */
		crc_result = crc16((unsigned char *)mbx_sram_addr, cfg->mailbox_size);
	}
	/* crc low 16 bit */
	write32(SOC_IPC_MBX_DATA7_ADDR(base, mailbox), ((cfg->mailbox_size << 16) | crc_result));
	/* send msg */
	write32(SOC_IPC_MBX_SEND_ADDR(base, mailbox), source);

	return IM_OK;
}

/*
 * recevie the mailbox data to ipc_msg
 * mailbox id of mailbox channel, cfg data of ipc_msg
 * IM_OK if success, IM_TIMEOUT_ERR fail
 */
int ipc_recv_msg(unsigned char mailbox, struct ipc_msg *cfg)
{
	unsigned int i;
	const unsigned int base = HISEE_IPC_BASE_ADDR;
	unsigned short crc_result, crc_check;
	unsigned int crc_size;

	if (!cfg)
		return IM_PARA_ERR;
	uart_printf_func("mbox-%d rec\n", mailbox);
	uart_printf_func("[IPCMBXSOURCE]:%x\n", read32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox)));
	uart_printf_func("[IPCMBXDSTATUS]:%x\n", read32(SOC_IPC_MBX_DSTATUS_ADDR(base, mailbox)));
	uart_printf_func("[IPCMBXMODE]:%x\n", read32(SOC_IPC_MBX_MODE_ADDR(base, mailbox)));
	for (i = 0; i < MAX_MAIL_SIZE; i++)
		uart_printf_func("[IPCMBXDATA%d]:%x\n", i, read32((SOC_IPC_MBX_DATA0_ADDR(base, mailbox) +
				 i * sizeof(unsigned int))));
	/* read data from ipc mailbox */
	for (i = 0; i < MAX_MAIL_SIZE; i++)
		cfg->data[i] = read32((SOC_IPC_MBX_DATA0_ADDR(base, mailbox) + i * sizeof(unsigned int)));

	/*
	 * find mailbox sram balock addr By searching Memory block allocation information
	 * return cfg struct to user and copy data by user
	 */
	cfg->mailbox_addr = (unsigned int)(uintptr_t)mbx_sram_addr_get(mailbox);
	cfg->mailbox_size = mbx_sram_size_get(mailbox);
	if (cfg->mailbox_addr == 0)
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
	/* The high 16 bits of data7 is crc size */
	crc_size = (unsigned short)((cfg->data[BUF_ID7] & CRC_SIZE_MASK) >> 16);
	if ((crc_size > 0) && (crc_size == cfg->data[1]) && (crc_size <= cfg->mailbox_size)) {
		crc_check = crc16((unsigned char *)(uintptr_t)cfg->mailbox_addr, crc_size);
		crc_result = (unsigned short)(cfg->data[BUF_ID7] & CRC_RESULT_MASK);
		if (crc_check != crc_result) {
			uart_printf_func("crc check error\n");
			/* clear irq */
			write32(SOC_IPC_MBX_ICLR_ADDR(base, mailbox), BIT(AP_SOURCE));
			return -IM_STATUS_ERR;
		}
	}

	cfg->mode = read32(SOC_IPC_MBX_MODE_ADDR(base, mailbox)) & MBOX_MODE_MASK;
	cfg->mailbox_id = mailbox;

	/* write back zero, if read success */
	write32(SOC_IPC_MBX_DATA1_ADDR(base, mailbox), 0);
	/* clear irq */
	write32(SOC_IPC_MBX_ICLR_ADDR(base, mailbox), BIT(AP_SOURCE));

	return IM_OK;
}

#ifdef CONFIG_TEST_IPC
void ipc_dump_msg(unsigned char mailbox)
{
	unsigned int i;
	unsigned int base = HISEE_IPC_BASE_ADDR;

	uart_printf_func("mbox%d dump\n", mailbox);
	uart_printf_func("[IPCMBXSOURCE]:%x\n", read32(SOC_IPC_MBX_SOURCE_ADDR(base, mailbox)));
	uart_printf_func("[IPCMBXDSTATUS]:%x\n", read32(SOC_IPC_MBX_DSTATUS_ADDR(base, mailbox)));
	uart_printf_func("[IPCMBXMODE]:%x\n", read32(SOC_IPC_MBX_MODE_ADDR(base, mailbox)));
	for (i = 0; i < MAX_MAIL_SIZE; i++)
		/* 4:size of mailbox data */
		uart_printf_func("[IPCMBXDATA%d]:%x\n", i, read32(SOC_IPC_MBX_DATA0_ADDR(base, mailbox) + i * 4));
}
#endif
