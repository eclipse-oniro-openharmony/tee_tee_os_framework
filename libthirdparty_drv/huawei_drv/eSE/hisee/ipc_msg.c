/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos to hisee ipc driver.
 * Create: 2019/9/30
 */

#include "ipc_msg.h"
#include <mem_ops.h>
#include <register_ops.h>
#include <sre_sys.h>
#include <sre_hwi.h>
#include <sre_typedef.h> /* UINT32 */
#include <drv_module.h>
#include <secure_gic_common.h>
#include "tee_log.h" /* uart_printf_func */
#include "ipc_call.h"
#include "ipc_a.h"
#include "tee_defines.h"
#include "pthread.h"
#include "platform.h"


/*  DEBUG_HISEE_IPC_TEST enable HISEE_IPC_TEST in teeos ,closed in normal version */

extern int __ipc_smc_switch(unsigned int irq);
unsigned int g_ipc_cb_current_num;
struct ipc_cb_st g_ipc_cb_ops[MAX_IPC_CALLBACK_NUM];

/*
 * Description: this  ipc map table just list the ipc channel which have been used currently,
 * like the MODEM_BBE16 and MODEM_A9,which in austin platform, soc reserve it
 * but we don't need it, so delete them in the table
 */
struct ipc_hd_map inse_ipc_map[] = {
#if defined(DEBUG_HISEE_IPC_TEST)
	{IPC_TEE_FASTMBOX, IPC_TEE_MBXFIQ, MBOX_FAST},         /* INSE receive irq--not used right now */
#endif
	{IPC_AP_FASTMBOX, IPC_ATF_MBXFIQ, MBOX_FAST},         /* ATF mbox-13 receive irq */
};

static int echo(struct ipc_msg *msg)
{
	unsigned int i = 0;

	/* 2:number of msg data block */
	for (i = 0; i < 2; i++)
		uart_printf_func("hisee_echo %x\n", msg->data[i]);
	msg->data[1] = 0xbeefbeef;
	return IM_OK;
}

/*
 * user registers callback function
 * 0 ok; orther fail
 */
int ipc_msg_req_callback(unsigned int obj, unsigned int cmd, int (*func)(struct ipc_msg *))
{
	unsigned int i;

	if (!func || obj >= MAX_CMD_OBJ || cmd >= MAX_CMD_MODE) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_PARA_ERR;
	}

	if (g_ipc_cb_current_num >= MAX_IPC_CALLBACK_NUM) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_PARA_ERR;
	}

	for (i = 0; i < g_ipc_cb_current_num; i++) {
		if ((g_ipc_cb_ops[i].obj == obj) &&
			(g_ipc_cb_ops[i].cmd == cmd) &&
			(g_ipc_cb_ops[i].ipc_msg_cb != echo)) {
			uart_printf_func("%s %d:\r\n", __func__, __LINE__);
			return IM_CONFLICT_ERR;
		}
	}
	g_ipc_cb_ops[g_ipc_cb_current_num].ipc_msg_cb = func;
	g_ipc_cb_ops[g_ipc_cb_current_num].obj = obj;
	g_ipc_cb_ops[g_ipc_cb_current_num].cmd = cmd;
	g_ipc_cb_current_num++;
	return IM_OK;
}

/*
 * user unregisters callback function
 * 0 ok; other fail
 */
int ipc_msg_put_callback(unsigned int obj, unsigned int cmd)
{
	unsigned int i;

	if (obj >= MAX_CMD_OBJ || cmd >= MAX_CMD_MODE) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_PARA_ERR;
	}

	for (i = 0; i < g_ipc_cb_current_num; i++) {
		if ((g_ipc_cb_ops[i].obj == obj) && (g_ipc_cb_ops[i].cmd == cmd)) {
			g_ipc_cb_ops[i].ipc_msg_cb = echo;
			break;
		}
	}
	return IM_OK;
}

/*
 * user used to get mailbox size
 * return mailbox size
 */
unsigned int ipc_msg_mbx_size_get(unsigned int processor_id)
{
	unsigned char mailbox_id = 0;

	switch (processor_id) {
	case OBJ_INSE:
		mailbox_id = IPC_INSE_FASTMBOX;
		break;
	case OBJ_TEEOS:
		mailbox_id = IPC_TEE_FASTMBOX;
		break;
	default:
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_PARA_ERR;
	}

	return mbx_sram_size_get(mailbox_id);
}

/*
 * user used to send msg
 * 1: ack, -1: ipc, 0: none
 */
int ipc_msg_send(unsigned int processor_id, struct ipc_msg *msg)
{
	int ret;

	if (!msg)
		return IM_PARA_ERR;

	msg->mode = MBOX_AUTOACK; /* only support async msg */

	switch (processor_id) {
	case OBJ_INSE:                  /* InSE core */
		msg->dest_id = BIT(INSE_SOURCE);
		msg->mailbox_id = IPC_INSE_FASTMBOX;
		break;
	default:
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		return IM_PARA_ERR;
	}

	ret = ipc_send_msg(msg);
	return ret;
}

#ifdef IPC_TEST
/* interrupt process message receiving  function */
static void ipc_msg_receive(unsigned char mailbox)
{
	unsigned int i = 0;
	unsigned char obj, cmd;
	struct ipc_msg msg;

	/* read msg from hardware */
	ipc_recv_msg(mailbox, &msg);

	/* receive progress */
	obj = msg.cmd_mix.cmd_obj;
	cmd = msg.cmd_mix.cmd;

	if (obj >= MAX_CMD_OBJ || cmd >= MAX_CMD_MODE) {
		uart_printf_func("%s %d:\r\n", __func__, __LINE__);
		echo((struct ipc_msg *)&msg);
	} else {
		for (i = 0; i < g_ipc_cb_current_num; i++) {
			if (!g_ipc_cb_ops[i].ipc_msg_cb) {
				uart_printf_func("%s %d:function pointer is NULL!\r\n", __func__, __LINE__);
				return;
			}
			if ((g_ipc_cb_ops[i].obj == obj) && (g_ipc_cb_ops[i].cmd == cmd)) {
				(void)g_ipc_cb_ops[i].ipc_msg_cb((struct ipc_msg *)&msg);
				return;
			}
		}
		if (i == g_ipc_cb_current_num) {
			uart_printf_func("%s %d:\r\n", __func__, __LINE__);
			echo((struct ipc_msg *)&msg);
		}
	}
}
#endif
/*
 * tatic void  ipc_msg_interrupt
 * interrupt proccese function
 */
void ipc_msg_interrupt(unsigned int irq)
{
#if defined(DEBUG_HISEE_IPC_TEST)
	/* process ipc irq in test version */
	if (irq == IPC_TEE_MBXFIQ)
		ipc_msg_receive(IPC_TEE_FASTMBOX);
	else
		(void)__ipc_smc_switch(irq);
#else
	(void)__ipc_smc_switch(irq);
#endif
}

static void ipc_msg_preinit(void)
{
	unsigned int i;

	g_ipc_cb_current_num = 0;

	/* operation table init */
	for (i = 0; i < MAX_IPC_CALLBACK_NUM; i++) {
		g_ipc_cb_ops[i].ipc_msg_cb = echo;
		g_ipc_cb_ops[i].obj = MAX_CMD_OBJ;
		g_ipc_cb_ops[i].cmd = MAX_CMD_MODE;
	}

}

#if defined(DEBUG_HISEE_IPC_TEST)
/*
 * test code for ipc tx/rx in interrupt
 * hisee_ipc_test_cmd_proc
 * receiv data from ipc mailbox, then send negative data back
 */
int hisee_ipc_test_cmd_proc(struct ipc_msg *p_msg)
{
	struct cmd_parse *p_cmd = NULL;
	uint32_t *mbx_tx_addr = NULL;
	uint32_t  mbx_tx_size;
	uint32_t *mbx_rx_addr = NULL;
	uint32_t  mbx_rx_size;
	uint32_t i;

	if (!p_msg)
		return IM_PARA_ERR;

	p_cmd = &(p_msg->cmd_mix);

	mbx_tx_addr = (uint32_t *)mbx_sram_addr_get(IPC_INSE_FASTMBOX);
	mbx_tx_size  = ipc_msg_mbx_size_get(OBJ_INSE);

	mbx_rx_addr = (uint32_t *)p_msg->mailbox_addr;
	mbx_rx_size = p_msg->mailbox_size;

	/* limit th tx size to rx size */
	if (mbx_tx_size > mbx_rx_size)
		mbx_tx_size = mbx_rx_size;
	/* read data from mailbox and write negative data back */
	mbx_tx_size = mbx_tx_size / sizeof(uint32_t);
	while (mbx_tx_size > 0) {
		*mbx_tx_addr = ~(*mbx_rx_addr);
		mbx_rx_addr++;
		mbx_tx_addr++;
		mbx_tx_size--;
	}
	/* DATA7 is used by crc */
	for (i = 1; i < (MAX_MAIL_SIZE - 1); i++)
		p_msg->data[i] = ~p_msg->data[i];

	/* send loopbak ipc msg to hisee */
	p_cmd->cmd_type = TYPE_INSE_A;
	p_cmd->cmd_obj = OBJ_INSE;
	p_cmd->cmd_src = OBJ_TEEOS;
	p_cmd->cmd = CMD_TEST;

	p_msg->mailbox_addr = 0;
	p_msg->mailbox_size = 0;

	if (ipc_msg_send(OBJ_INSE, p_msg) != IM_OK)
		uart_printf_func("test_ipc_cmd send fail\n");

	return 0;
}
#endif


pthread_mutex_t g_ipc_lock;
pthread_mutex_t g_vote_lock;

pthread_mutex_t *get_ipc_lock(void)
{
	return &g_ipc_lock;
}

pthread_mutex_t *get_vote_lock(void)
{
	return &g_vote_lock;
}

int ipc_msg_init(void)
{
	int ret;
	unsigned int i = 0;

	ipc_msg_preinit();

#if defined(DEBUG_HISEE_IPC_TEST)
	uart_printf_func("test hisee tee ipc\n");
	ret = ipc_msg_req_callback(OBJ_TEEOS, CMD_TEST, hisee_ipc_test_cmd_proc);
	if (ret != IM_OK)
		uart_printf_func("test ipc init fail fail\n");
#endif

	/* request irq */
	for (i = 0; i < ARRY_SIZE(inse_ipc_map); i++) {
		ret = (int)SRE_HwiCreate(inse_ipc_map[i].mbx_irq, 0x0, 0x0, ipc_msg_interrupt, inse_ipc_map[i].mbx_irq);
		if (ret != SRE_OK) {
			uart_printf_func("HiseeIpcCreate irq %d errorNO 0x%x\n", inse_ipc_map[i].mbx_irq, ret);
			return ret;
		}
		ret = (int)SRE_HwiEnable(inse_ipc_map[i].mbx_irq);
		if (ret != SRE_OK) {
			uart_printf_func("HiseeIpcEnable irq %d errorNO 0x%x\n", inse_ipc_map[i].mbx_irq, ret);
			return ret;
		}
	}

	/* Create an ipc seamphore, the number is 1 . */
	ret = pthread_mutex_init(&g_ipc_lock, NULL);
	if (ret != SRE_OK)
		uart_printf_func("%s:Create g_ipc_lock failed! ret = %x\n", __func__, ret);

	ret = pthread_mutex_init(&g_vote_lock, NULL);
	if (ret != SRE_OK)
		uart_printf_func("%s:Create g_vote_lock mutex failed! ret = %x\n", __func__, ret);

	uart_printf_func("HiseeIpcInitOK\n");
	return ret;
}

int ipc_msg_resume(void)
{
	UINT32  i;
	UINT32 ret;

	/* for HISEE IPC FIQ */
	for (i = 0; i < ARRY_SIZE(inse_ipc_map); i++) {
		ret = SRE_HwiResume(inse_ipc_map[i].mbx_irq, 0, INT_SECURE);
		if (ret) {
			uart_printf_func("SRE_HwiResume %u failed, error %d\n", inse_ipc_map[i].mbx_irq, ret);
			return -1;
		}

		ret = SRE_HwiEnable(inse_ipc_map[i].mbx_irq);
		if (ret) {
			uart_printf_func("SRE_HwiEnable %u failed, error %d\n", inse_ipc_map[i].mbx_irq, ret);
			return -1;
		}
	}

	/*
	 * GIC has already been re-initialized by kernel,
	 * so no need to invoke GIC_secure_cpuInterface_ctrl_init;
	 */

	return 0;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)

DECLARE_TC_DRV(
	hisee_ipc_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	ipc_msg_init,
	NULL,
	NULL,
	NULL,
	ipc_msg_resume
);

#endif
