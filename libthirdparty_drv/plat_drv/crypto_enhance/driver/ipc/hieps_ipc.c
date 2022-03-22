/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps ipc driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <register_ops.h>
#include <sre_typedef.h>
#include <sre_hwi.h>
#include <pthread.h>
#include <tee_log.h>
#include <secure_gic_common.h>
#include <hieps_errno.h>
#include <hieps_ipc.h>
#include <hieps_power.h>
#include <hieps_pm.h>
#include <hieps_common.h>
#include <hieps_timer.h>
#include <soc_eps_ipc_interface.h>


/* IPC initializtion flag. */
static int32_t g_ipc_init_flag;
/* The number of callback functions. */
static uint32_t g_ipc_callback_number;
/* Callback table. */
static ipc_cb_st g_ipc_callback_list[MAX_IPC_CALLBACK_NUM];

/* Hieps ipc channel info. */
static struct ipc_hd_map hieps_ipc_map[] = {
	/* recv_mbx_id    send_mbx_id         mbx_irq          mbx_type    processor     source */
	{IPC0_FROM_EPS,   IPC0_TO_EPS,   HIEPS_IPC0_FAST_IRQ,   MBOX_FAST,   OBJ_HIEPS,     HIEPS_SOURCE},
	{IPC_NORMAL_MBX, IPC_NORMAL_MBX, HIEPS_IPC0_NORMAL_IRQ, MBOX_NORMAL, MAX_CMD_OBJ, INVALID_SOURCE},
};


/*
 * @brief      : hieps_ipc_echo : print ipc data registers.
 *
 * @param[in]  : msg: ipc message struct.
 *
 * @return     : OK.
 */
static int32_t hieps_ipc_echo(ipc_msg_t *msg)
{
	uint32_t i;

	for (i = 0; i < MAX_MAIL_SIZE; i++)
		tloge("Echo 0x%x\n", msg->data[i]);

	return HIEPS_OK;
}

/*
 * @brief      : hieps_get_ipc_callback_number : get the current numbers of
		 ipc callback functions.
 *
 * @return     : the number of callback functions.
 */
static uint32_t hieps_get_ipc_callback_number(void)
{
	return g_ipc_callback_number;
}

/*
 * @brief      : hieps_update_ipc_callback_number : update the number of callback functions.
 */
static void hieps_update_ipc_callback_number()
{
	g_ipc_callback_number++;
}

/*
 * @brief      : hieps_clear_ipc_callback : Clear ipc callback talble.
 */
static void hieps_clear_ipc_callback()
{
	uint32_t i;

	g_ipc_callback_number = 0;
	for (i = 0; i < MAX_IPC_CALLBACK_NUM; i++) {
		g_ipc_callback_list[i].ipc_msg_cb = (IPCMSGCB)hieps_ipc_echo;
		g_ipc_callback_list[i].obj = MAX_CMD_OBJ;
		g_ipc_callback_list[i].cmd = MAX_CMD_MODE;
	}
}

/*
 * @brief      : hieps_ipc_msg_req_callback : register callback function for ipc.
 *
 * @param[in]  : obj: operate object.
 * @param[in]  : cmd: operate command.
 * @param[in]  : func: callback function.
 *
 * @return     : IM_OK, successfuly, other value for error.
 */
int32_t hieps_ipc_msg_req_callback(uint32_t obj, uint32_t cmd, IPCMSGCB func)
{
	uint32_t i;
	uint32_t callback_number;

	/* Check parameters. */
	if ((func == NULL) || (obj >= MAX_CMD_OBJ) || (cmd >= MAX_CMD_MODE)) {
		tloge("hieps ipc: Invalid para: obj:%d, cmd:%d\n", obj, cmd);
		return HIEPS_PARAM_ERR;
	}

	callback_number = hieps_get_ipc_callback_number();

	/* Check whether hieps ipc callback list overflow. */
	if (callback_number >= MAX_IPC_CALLBACK_NUM) {
		tloge("hieps ipc: callback_number:%d overflow obj:%d, cmd:%d\n",\
			callback_number, obj, cmd);
		return HIEPS_ALLOC_ERR;
	}

	/* Check whether there is already a callback for the obj&cmd. */
	for (i = 0; i < callback_number; i++) {
		if ((g_ipc_callback_list[i].obj == obj) &&\
		    (g_ipc_callback_list[i].cmd == cmd) &&\
		    (g_ipc_callback_list[i].ipc_msg_cb != (IPCMSGCB)hieps_ipc_echo)) {
			    tloge("hieps ipc:callback already exist obj:%d, cmd:%d\n",\
					    obj, cmd);
			    return HIEPS_CONFLICT_ERR;
		}
	}

	/* Add the new callback function to list. */
	g_ipc_callback_list[g_ipc_callback_number].ipc_msg_cb = func;
	g_ipc_callback_list[g_ipc_callback_number].obj = obj;
	g_ipc_callback_list[g_ipc_callback_number].cmd = cmd;
	hieps_update_ipc_callback_number();

	return HIEPS_OK;
}

/*
 * @brief      : hieps_get_ipc_share_memory_size : get the memory size of specify hisee ipc.
 *
 * @param[in]  : mbx_id : mailbox channel.
 *
 * @return     : size
 */
static int32_t hieps_get_ipc_share_memory_size(uint8_t mbx_id)
{
	ipc_mbx_distribution_t *mbx_space = NULL;

	if (mbx_id >= MAX_MAILBOX_NUM)
		return HIEPS_PARAM_ERR;

	mbx_space = (ipc_mbx_distribution_t *)IPC_MBX_DISTRIBUTION;
	if (IPC_MBX_SPACE_INIT != mbx_space->flag) {
		tloge("hieps ipc:Mailbox memory hasnot been intialized!\n");
		return HIEPS_ALLOC_ERR;
	}

	return mbx_space->ipc[mbx_id].size;
}

/*
 * @brief      : hieps_get_ipc_share_memory_addr: get the memory address of specify ipc
 *		 in hisee mailbox ram.
 *
 * @param[in]  : mbx_id: mailbox channel.
 *
 * @return     : char pointer
 */
static int8_t *hieps_get_ipc_share_memory_addr(uint8_t mbx_id)
{
	ipc_mbx_distribution_t *mbx_space = NULL;

	if (mbx_id >= MAX_MAILBOX_NUM)
		return NULL;

	mbx_space = (ipc_mbx_distribution_t *)IPC_MBX_DISTRIBUTION;
	if (mbx_space->flag != IPC_MBX_SPACE_INIT) {
		tloge("hieps ipc:Mailbox memory hasnot been intialized!\n");
		return NULL;
	}

	return (int8_t *)(uintptr_t)mbx_space->ipc[mbx_id].addr;
}

/*
 * @brief      : hieps_request_mailbox : config to use ipc.
 *
 * @param[in]  : cfg : configure data.
 *
 * @return     : HIEPS_OK: successful, others: failed.
 */
static uint32_t hieps_request_mailbox(const ipc_msg_t *cfg)
{
	uint32_t timeout, base, source;
	uint32_t ret, value;
	uint8_t mailbox;

	mailbox = cfg->mailbox_id;
	base = HIEPS_IPC_BASE_ADDR;
	source = BIT(AP0_SOURCE);

	/* Unlock IPC register lock. */
	write32(SOC_EPS_IPC_IPC_LOCK_ADDR(base), REG_UNLOCK_KEY);

	/* wait mailbox idle */
	timeout = IPC_WAIT_IDLE_TIMEOUT; /* Loop 2000 times. */
	value = read32(SOC_EPS_IPC_MBX_MODE_ADDR(base, mailbox));
	while ((MBOX_IDLE_STAT != value) && (timeout)) {
		hieps_udelay(100); /* every loop 100us. */
		value = read32(SOC_EPS_IPC_MBX_MODE_ADDR(base, mailbox));
		timeout--;
	}

	if (0 == timeout) {
		tloge("hieps:wait mailbox idle timeout!\n");
		ret = HIEPS_TIMEOUT_ERR;
		goto exit;
	}

	/* request to use mailbox */
	value = read32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mailbox));
	if (0 == (value & source)) {
		write32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mailbox), source);
	}

	/* Check whether request successfully. */
	timeout = IPC_WAIT_REQUEST_TIMEOUT; /* Loop 20 times. */
	value = read32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mailbox));
	while (((value & source) == 0) && (timeout)) {
		write32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mailbox), source);
		hieps_udelay(100); /* every loop 100us. */
		value = read32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mailbox));
		timeout--;
	}

	if (0 == timeout) {
		tloge("hieps:request mailbox timeout!\n");
		ret = HIEPS_TIMEOUT_ERR;
		goto exit;
	}

	ret = HIEPS_OK;
exit:
	return ret;
}

/*
 * @brief      : hieps_ipc_config : config the ipc register to send message.
 *
 * @param[in]  : cfg : the data information.
 *
 * @return     : HIEPS_OK, successfule, others, failed.
 */
static uint32_t hieps_ipc_config(const ipc_msg_t *cfg)
{
	uint32_t ret, base, source;
	uint8_t i, mailbox;

	mailbox = cfg->mailbox_id;
	base = HIEPS_IPC_BASE_ADDR;
	source = BIT(AP0_SOURCE);

	if (HIEPS_STATUS_DOWN == hieps_get_status()) {
		tloge("hieps ipc: hieps is power off!\n");
		ret = HIEPS_ERROR;
		goto exit;
	}

	ret = hieps_set_access_flag(HIEPS_ACCESS);
	if (HIEPS_OK != ret) {
		tloge("hieps ipc: set access flag failed!\n");
		goto exit;
	}

	ret = hieps_request_mailbox(cfg);
	if (HIEPS_OK != ret) {
		tloge("hieps:requset mailbox failed1\n");
		goto err_clear_access;
	}

	/* set irq mask */
	write32(SOC_EPS_IPC_MBX_IMASK_ADDR(base, mailbox),\
		~(source | cfg->dest_id));

	/* set mailbox workmode */
	write32(SOC_EPS_IPC_MBX_MODE_ADDR(base, mailbox),\
		(cfg->mode & MBOX_MODE_MASK));

	/* set mailbox reg data */
	for (i = 0; i < MAX_MAIL_SIZE; i++) {
		/* Every data register is 32bit, that is 4 Byte. */
		write32(SOC_EPS_IPC_MBX_DATA0_ADDR(base, mailbox) + i * 4,\
			cfg->data[i]);
	}

	/* send msg */
	write32(SOC_EPS_IPC_MBX_SEND_ADDR(base, mailbox), source);

err_clear_access:
	if (HIEPS_OK != hieps_set_access_flag(HIEPS_DONOT_ACCESS)) {
		tloge("hieps ipc: clear access flag failed!\n");
	}

exit:
	return ret;
}

/*
 * @brief      : hieps_ic_find_map_by_processor : find the specify ipc.
 *
 * @param[in]  : processor_id : the processor.
 *
 * @return     : the ipc info.
 */
static struct ipc_hd_map *hieps_ipc_find_map_by_processor(uint8_t processor_id)
{
	uint32_t i;

	if (processor_id < MAX_CMD_OBJ) {
		for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
			if (processor_id == hieps_ipc_map[i].processor)
				return &hieps_ipc_map[i];
		}
	}

	tloge("hieps ipc: invalid process %d!\n", __func__, __LINE__, processor_id);
	return NULL;
}

/*
 * @brief      : ipc_msg_send : send message to destination.
 *
 * @param[in]  : processor_id: destination.
 * @param[in]  : msg: the message to be send.
 * @param[in]  : mode: send mode, sync or async.
 *
 * @return     : OK, successfuly; others value, failed.
 */
int32_t hieps_ipc_send(uint32_t processor_id, ipc_msg_t *msg, uint32_t mode)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t sre_ret;
	struct ipc_hd_map *p_ipc_map = NULL;

	if ((NULL == msg) || ((SYNC_CMD != mode) && (ASYNC_CMD != mode))) {
		tloge("hieps ipc:Invalid param! mode:0x%x, process:0x%x!\n",\
			mode, processor_id);
		return HIEPS_PARAM_ERR;
	}

	if (IPC_INIT_FINISH_FLAG != g_ipc_init_flag) {
		tloge("hieps ipc:IPC module is not ready!\n");
		return HIEPS_STATUS_ERR;
	}

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.ipc_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:wait hieps_ipc_lock failed: 0x%x!\n", sre_ret);
		ret = HIEPS_MUTEX_ERR;
		goto exit;
	}

	p_ipc_map = hieps_ipc_find_map_by_processor(processor_id);
	if (NULL == p_ipc_map) {
		tloge("hieps ipc: Invalid processor: %x\n", processor_id);
		ret = HIEPS_INVALID_PROC_ERR;
		goto exit;
	}

	msg->mode = mode;
	msg->dest_id = BIT(p_ipc_map->source);
	msg->mailbox_id = p_ipc_map->send_mbx_id;

	ret = hieps_ipc_config(msg);
	if (ret != HIEPS_OK) {
		tloge("hieps ipc:Send IPC failed!ret=0x%x!\n", ret);
		goto exit;
	}

exit:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.ipc_lock);
	if (SRE_OK != sre_ret)
		tloge("hieps:unlock hieps_ipc_lock failed: 0x%x!\n", sre_ret);

	return ret;
}

/*
 * @brief      : hieps_cmd_handle : handle the ipc message.
 *
 * @param[in]  : msg: the ipc message which was received.
 */
static void hieps_cmd_handle(ipc_msg_t *msg)
{
	uint8_t obj, cmd;
	uint32_t i, callback_number;
	IPCMSGCB callback_func = NULL;

	/* receive process */
	obj = msg->cmd_mix.cmd_obj;
	cmd = msg->cmd_mix.cmd;

	if ((obj >= MAX_CMD_OBJ) || (cmd >=  MAX_CMD_MODE)) {
		tloge("hieps ipc:receive callback para err. obj:%d, cmd:%d\n",\
			obj, cmd);
		hieps_ipc_echo(msg);
		return;
	}

	callback_number = hieps_get_ipc_callback_number();
	for (i = 0; i < callback_number; i++) {
		if ((g_ipc_callback_list[i].obj == obj) &&\
		    (g_ipc_callback_list[i].cmd == cmd)) {
			callback_func = g_ipc_callback_list[i].ipc_msg_cb;
			break;
		}
	}

	if ((i == callback_number) || (NULL == callback_func)) {
		tloge("hieps ipc:no callback for obj:%d, cmd:%d, current_num:%d\n",\
			obj, cmd, callback_number);
		hieps_ipc_echo(msg);
		return;
	}

	/* Call the callback function. */
	callback_func(msg);
}

/*
 * @brief      : hieps_ipc_receive : receive ipc message from hardware.
 *
 * @param[in]  : ipc: ipc id
 * @param[in]  : mailbox: mailbox channel.
 */
static void hieps_ipc_receive(uint8_t mailbox)
{
	uint32_t i, value;
	uint32_t source = BIT(AP0_SOURCE);
	uint32_t base = HIEPS_IPC_BASE_ADDR;
	ipc_msg_t cfg;

	(void)memset_s(&cfg, sizeof(cfg), 0x0, sizeof(cfg));
	if (HIEPS_STATUS_DOWN == hieps_get_status()) {
		tloge("hieps ipc: hieps is power off!\n");
		return;
	}

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_ACCESS)) {
		tloge("hieps ipc: hieps set access flag failed!\n");
		/* clear irq */
		write32(SOC_EPS_IPC_MBX_ICLR_ADDR(base, mailbox), source);
		return;
	}

	/* read data form ipc data registers */
	for (i = 0; i < MAX_MAIL_SIZE; i++)
		/* Every data register is 32bit, that is 4 Byte. */
		cfg.data[i] = read32(SOC_EPS_IPC_MBX_DATA0_ADDR(base, mailbox) + i * 4);

	value = read32(SOC_EPS_IPC_MBX_MODE_ADDR(base, mailbox));
	cfg.mode = value & MBOX_MODE_MASK;
	cfg.mailbox_id = mailbox;
	cfg.mailbox_addr = (u32)(uintptr_t)hieps_get_ipc_share_memory_addr(mailbox);
	cfg.mailbox_size = hieps_get_ipc_share_memory_size(mailbox);

	/* clear irq */
	write32(SOC_EPS_IPC_MBX_ICLR_ADDR(base, mailbox), source);

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_DONOT_ACCESS))
		tloge("hieps clear access flag failed!\n");

	hieps_cmd_handle(&cfg);
}

/*
 * @brief      : hieps_ipc_recv_ack : receive ack irq.
 *
 * @param[in]  : ipc_id : ipc id.
 * @param[in]  : mbx_id : mailbox channel.
 */
static void hieps_ipc_recv_ack(uint8_t mbx_id)
{
	uint32_t source = BIT(AP0_SOURCE);
	uint32_t base = HIEPS_IPC_BASE_ADDR;

	if (HIEPS_STATUS_DOWN == hieps_get_status()) {
		tloge("hieps ipc:hieps is power off!\n");
		return;
	}

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_ACCESS)) {
		tloge("hieps ipc:set access flag failed!\n");
		return;
	}

	/* clear irq */
	write32(SOC_EPS_IPC_MBX_ICLR_ADDR(base, mbx_id), source);

	/* release mailbox */
	write32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mbx_id), source);

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_DONOT_ACCESS))
		tloge("hieps clear access flag failed!\n");

	return;
}

/*
 * @brief      : hieps_ipc_is_ack : judge a ipc irq whether a ack irq.
 *
 * @param[in]  : ipc_id: ipc id.
 * @param[in]  : mbx_id: mailbox channel.
 *
 * @return     : IS_ACK, ack irq; NOT_ACK, ipc irq, NONE, others.
 */
static int32_t hieps_ipc_is_ack(uint8_t mbx_id)
{
	uint32_t irq_status, ret, reg;
	uint8_t source = AP0_SOURCE;
	uint32_t base = HIEPS_IPC_BASE_ADDR;

	if (HIEPS_STATUS_DOWN == hieps_get_status()) {
		tloge("hieps ipc: hieps is power off!\n");
		return NONE;
	}

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_ACCESS)) {
		tloge("hieps ipc: set access flag failed!\n");
		return NONE;
	}

	irq_status = read32(SOC_EPS_IPC_CPU_IMST_ADDR(base, source));
	if (irq_status & BIT(mbx_id)) {
		reg = read32(SOC_EPS_IPC_MBX_SOURCE_ADDR(base, mbx_id));
		if ((BIT(source) == reg))
		    ret = IS_ACK;
		else
		    ret = NOT_ACK;
	} else {
		ret = NONE;
	}

	if (HIEPS_OK != hieps_set_access_flag(HIEPS_DONOT_ACCESS))
		tloge("hieps ipc: clear access flag failed!\n");

	return ret;
}

/*
 * @brief      : hieps_ipc_irq_handler : ipc interrupt handler.
 *
 * @param[in]  : irq_num: interrupt number.
 */
static void hieps_ipc_irq_handler(uint32_t irq)
{
	uint8_t i= 0;
	uint8_t mbx_id = 0;
	int32_t is_ack_ipc = 0;

	for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
		if ((irq == hieps_ipc_map[i].mbx_irq) &&\
		    (MBOX_FAST == hieps_ipc_map[i].mbx_type)) {
			/* fast mailbox */
			hieps_ipc_receive(hieps_ipc_map[i].recv_mbx_id);
			break;
		} else if ((irq == hieps_ipc_map[i].mbx_irq) && \
			   (MBOX_NORMAL == hieps_ipc_map[i].mbx_type)) {
			/* normal mailbox */
			for (mbx_id = 0; mbx_id < MAX_MAILBOX_NUM; mbx_id++) {
				is_ack_ipc = hieps_ipc_is_ack(mbx_id);
				if (IS_ACK == is_ack_ipc) {
					/* Receive ACK irq. */
					hieps_ipc_recv_ack(mbx_id);
				} else if (NOT_ACK == is_ack_ipc) {
					/* Receive normal mailbox, donot use now. */
					hieps_ipc_receive(mbx_id);
				}
			}
			break;
		}
	}
	return;
}

/**
 * @brief      : hieps_enable_ipc_irq : enable hieps ipc interrupt.
 */
void hieps_enable_ipc_irq(void)
{
	int32_t ret = 0;
	uint32_t i;
	uint32_t irq;

	for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
		irq = hieps_ipc_map[i].mbx_irq;
		ret += SRE_HwiEnable((HWI_HANDLE_T)irq);
	}

	if (ret != SRE_OK)
		tloge("hieps ipc:enable irq failed, errorNO 0x%x\n", ret);

	return;
}

/**
 * @brief      : hieps_disable_ipc_irq : disable hieps ipc interrupt.
 */
void hieps_disable_ipc_irq(void)
{
	int32_t ret = 0;
	uint32_t i;
	uint32_t irq;

	for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
		irq = hieps_ipc_map[i].mbx_irq;
		ret += SRE_HwiDisable((HWI_HANDLE_T)irq);
	}

	if (ret != SRE_OK)
		tloge("hieps ipc:disable irq failed, errorNO 0x%x\n", ret);

	return;
}

/*
 * @brief      : hieps_ipc_msg_init : ipc initiation.
 *
 * @return     : HIEPS_OK, successfule, Others, failed.
 */
int32_t hieps_ipc_init(void)
{
	int32_t ret;
	uint32_t i, irq;

	/* Clear the callback table. */
	hieps_clear_ipc_callback();

	/* request irq */
	for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
		irq = hieps_ipc_map[i].mbx_irq;
		ret = SRE_HwiCreate((HWI_HANDLE_T)(irq), HIEPS_IRQ_PRIO, INT_SECURE,\
			(HWI_PROC_FUNC)hieps_ipc_irq_handler, (HWI_ARG_T)irq);
		if (ret != SRE_OK) {
			tloge("hieps:SRE_HwiCreate irq %d errorNO 0x%x\n", irq, ret);
			return ret;
		}

		ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
		if (ret != SRE_OK) {
			tloge("hieps:SRE_HwiEnable irq %d errorNO 0x%x\n", irq, ret);
			return ret;
		}
	}

	g_ipc_init_flag = IPC_INIT_FINISH_FLAG;

	return ret;
}

/*
 * @brief      : hieps_ipc_resume : Resume hieps ipc config.
 *
 * @return     : HIEPS_OK, successfule, Others, failed.
 */
int32_t hieps_ipc_resume(void)
{
	int32_t ret;
	uint32_t i;
	uint32_t irq;

	/* Resume hieps ipc interrupt requestment. */
	for (i = 0; i < ARRY_SIZE(hieps_ipc_map); i++) {
		irq = hieps_ipc_map[i].mbx_irq;
		ret = SRE_HwiResume((HWI_HANDLE_T)(irq), HIEPS_IRQ_PRIO, INT_SECURE);
		if (ret != SRE_OK) {
			tloge("hieps ipc:SRE_HwiResume irq %d errorNO 0x%x\n", irq, ret);
			return ret;
		}

		ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
		if (ret != SRE_OK) {
			tloge("hieps ipc:SRE_HwiEnable irq %d errorNO 0x%x\n", irq, ret);
			return ret;
		}
	}

	return ret;
}



