/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos power driver.
 * Create: 2019/9/30
 */

#include "hisee.h"
#include <errno.h>
#include <sre_sys.h>
#include <mem_ops.h>
#include <register_ops.h> // write32
#include "mem_page_ops.h"
#include "sre_task.h"
#include "ipc_msg.h"
#include "ipc_call.h"
#include "ipc_a.h"
#include "se_hal.h"
#include "hisee_mailbox_ram_map.h"
#include <sys/usrsyscall_ext.h>
#include "pthread.h"
#include "tee_log.h" /* uart_printf_func */
#include "securec.h"
#include "sre_dev_relcb.h"
#ifdef MSP_EXT_TPDU
#include "hisee_tpdu.h"
#endif
#include "soc_sctrl_interface.h"

/* swith of HISEE sync mode */
#define HISEE_SYNC_MODE       SCARD_MODE_SYNC2
#define HISEE_POWER_UP_ADDR   SOC_SCTRL_SCBAKDATA10_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)
#define HISEE_POWER_UP_BIT    11
#define READ  0
#define WRITE 1
#define MIN(a, b)        ((a) < (b) ? (a) : (b))

static union se_power_vote_status g_power_vote_status;
extern int __ipc_smc_switch(unsigned int irq);
static int hisee_scard_release_cb(void *data);
static int inse_release_cb(const void *data);

int hisee_p61_factory_test(void)
{
	return 0;
}

enum se_power_status hisee_get_power_status(void)
{
	if (g_power_vote_status.value == SE_POWER_STATUS_OFF)
		return SE_POWER_STATUS_OFF;
	else
		return SE_POWER_STATUS_ON;
}

static unsigned int get_vote_cnt(unsigned int vote_id)
{
	if (vote_id == SE_API_ID)
		return g_power_vote_status.status.se_api;
	else
		return g_power_vote_status.status.inse_encrypt;
}

static void set_vote_cnt(unsigned int vote_id, unsigned int cur_vote_cnt)
{
	if (vote_id == SE_API_ID)
		g_power_vote_status.status.se_api = cur_vote_cnt;
	else
		g_power_vote_status.status.inse_encrypt = cur_vote_cnt;
}

static int hisee_set_power_vote_status(unsigned int vote_id, int power_cmd)
{
	unsigned int cur_vote_cnt;

	cur_vote_cnt = get_vote_cnt(vote_id);
	if (cur_vote_cnt > HISEE_MAX_VOTE_COUNT) {
		uart_printf_func("Vote is over the maximum number!\n");
		return HISEE_FAILURE;
	}

	if (power_cmd == TEE_HISEE_POWER_ON) {
		if (cur_vote_cnt == HISEE_MAX_VOTE_COUNT) {
			uart_printf_func("Vote is the maximum number!\n");
			return HISEE_FAILURE;
		}
		cur_vote_cnt++;
	} else {
		if (cur_vote_cnt == HISEE_MIN_VOTE_COUNT) {
			uart_printf_func("Vote is already zero!\n");
			return HISEE_SUCCESS;
		}
		cur_vote_cnt--;
	}
	set_vote_cnt(vote_id, cur_vote_cnt);

	return HISEE_SUCCESS;
}

int hisee_power_on(unsigned int vote_id)
{
	int ret;
	enum se_power_status power_status;

	if (vote_id >= MAX_VOTE_ID) {
		uart_printf_func("%s-%d:vote id is %d\n", __func__, __LINE__, vote_id);
		return HISEE_FAILURE;
	}

	ret = pthread_mutex_lock(get_vote_lock());
	if (ret != SRE_OK) {
		uart_printf_func("%s:Wait g_vote_lock failed: %x!\n", __func__, ret);
		return ret;
	}

	power_status = hisee_get_power_status();
	if (power_status == SE_POWER_STATUS_OFF) {
		/* power on hisee */
		ret = __ipc_smc_switch(TEE_HISEE_POWER_ON);
		if (ret != HISEE_SUCCESS) {
			uart_printf_func("%s:vote %d power on hisee failed: %d\n", __func__, vote_id, ret);
			ret = HISEE_FAILURE;
			goto err;
		}
	}

	ret = hisee_set_power_vote_status(vote_id, TEE_HISEE_POWER_ON);
	if (ret != HISEE_SUCCESS) {
		(void)__ipc_smc_switch(TEE_HISEE_POWER_OFF);
		uart_printf_func("%s:vote %d power off hisee failed: %d\n", __func__, vote_id, ret);
		ret = HISEE_FAILURE;
		goto err;
	}
err:
	if (pthread_mutex_unlock(get_vote_lock()) != SRE_OK) {
		ret = HISEE_FAILURE;
		uart_printf_func("%s:Release g_vote_lock failed: %x!\n", __func__, ret);
	}
	return ret;
}

int hisee_power_off(unsigned int vote_id)
{
	int ret;
	enum se_power_status power_status;

	if (vote_id >= MAX_VOTE_ID) {
		uart_printf_func("%s-%d:vote id is %d\n", __func__, __LINE__, vote_id);
		return HISEE_FAILURE;
	}

	ret = pthread_mutex_lock(get_vote_lock());
	if (ret != SRE_OK) {
		uart_printf_func("%s:Wait g_vote_lock failed: %x!\n", __func__, ret);
		return ret;
	}

	power_status = hisee_get_power_status();
	if (power_status == SE_POWER_STATUS_OFF) {
		uart_printf_func("%s: hisee is already off\n", __func__);
		ret = HISEE_SUCCESS;
		goto err;
	}

	/*
	 * vote then check is the vote_status if off,
	 * if the status is off, then power_off the hisee.
	 */
	ret = hisee_set_power_vote_status(vote_id, TEE_HISEE_POWER_OFF);
	if (ret != HISEE_SUCCESS) {
		uart_printf_func("%s:set power status failed: %d\n", __func__, ret);
		ret = HISEE_FAILURE;
		goto err;
	}

	power_status = hisee_get_power_status();
	if (power_status == SE_POWER_STATUS_OFF) {
		/* power off hisee */
		ret = __ipc_smc_switch(TEE_HISEE_POWER_OFF);
		if (ret != HISEE_SUCCESS) {
			uart_printf_func("%s: vote %d power off hisee failed: %d\n", __func__, vote_id, ret);
			/* recover the vote status if power off failed. */
			ret = hisee_set_power_vote_status(vote_id, TEE_HISEE_POWER_ON);
			if (ret != HISEE_SUCCESS)
				uart_printf_func("%s:recover power status failed: %d\n", __func__, ret);
			ret = HISEE_FAILURE;
			goto err;
		}
	}
err:
	if (pthread_mutex_unlock(get_vote_lock()) != SRE_OK) {
		ret = HISEE_FAILURE;
		uart_printf_func("%s:Release g_vote_lock failed: %x!\n", __func__, ret);
	}
	return ret;
}

/*
 * inse_disconnect: power off hisee.
 * HISEE_SUCCESS: power off successfuly
 * Others: power off failed.
 */
int inse_disconnect(const void *id)
{
	unsigned int vote_id;

	if (!id) {
		uart_printf_func("%s-%d\n", __func__, __LINE__);
		return HISEE_FAILURE;
	}

	vote_id = *(unsigned int *)id;
	uart_printf_func("inse disconnect: id is %d\n", vote_id);

	/* unregister se release callback to current task */
	(void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)inse_release_cb, id);

	return hisee_power_off(vote_id);
}

/*
 * inse_connect: power on hisee.
 * HISEE_SUCCESS: power on successfuly.
 * Others: power on failed.
 */
int inse_connect(void *id)
{
	int ret;
	unsigned int vote_id;

	if (!id) {
		uart_printf_func("%s-%d\n", __func__, __LINE__);
		return HISEE_FAILURE;
	}

	vote_id = *(unsigned int *)id;
	uart_printf_func("inse connect: id is %d\n", vote_id);

	ret = hisee_power_on(vote_id);
	if (ret) {
		uart_printf_func("scard connect power on failed:%d\n", ret);
		return ret;
	}

	/*
	 * Note: put this at the end of this function after connect successfully,
	 * this register se disconnect callback to current task,
	 * in case of se disconnect call missing when task exit
	 */
	ret = (int)task_register_devrelcb((DEV_RELEASE_CALLBACK)inse_release_cb, id);
	if (ret) {
		(void)inse_disconnect(id);
		uart_printf_func("SRE_TaskRegister_DevRelCb for inse error:%d\n", ret);
		return ret;
	}

	return HISEE_SUCCESS;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int hisee_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len)
{
	int ret;
	(void)p_atr;
	(void)atr_len;

	uart_printf_func("hisee scard connect\n");
	ret = hisee_power_on(SE_API_ID);
	if (ret) {
		uart_printf_func("scard connect power on failed:%d\n", ret);
		return ret;
	}

	/*
	 * Note: put this at the end of this function after connect successfully,
	 * this register se disconnect callback to current task,
	 * in case of se disconnect call missing when task exit
	 */
	ret = (int)task_register_devrelcb((DEV_RELEASE_CALLBACK)hisee_scard_release_cb, NULL);
	if (ret) {
		(void)hisee_scard_disconnect(0);
		uart_printf_func("SRE_TaskRegister_DevRelCb for scard error:%d\n", ret);
		return ret;
	}

	return 0;
}

int hisee_scard_disconnect(int reader_id)
{
	uart_printf_func("hisee scard disconnect\n");
	/* unregister se release callback to current task */
	(void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)hisee_scard_release_cb, NULL);

	return hisee_power_off(SE_API_ID);
}
#pragma GCC diagnostic pop

int hisee_vote_up(void)
{
	int ret;

	ret = __ipc_smc_switch((unsigned int)TEE_HISEE_ON); /* checking cos ready or not and keeping HISEE power on */
	if (ret == SE_STAT_COS_READY)
		return 0;
	uart_printf_func("cos not ready: %d\n", ret);
	return -1;

}

void hisee_vote_down(void)
{
	(void)__ipc_smc_switch((unsigned int)TEE_HISEE_OFF); /* used for notify HISEE can be shutdown */
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static int hisee_scard_release_cb(void *data)
{
	uart_printf_func("hisee scard release cb called.\n");
	if (!data) {
		uart_printf_func("%s-%d\n", __func__, __LINE__);
		return HISEE_FAILURE;
	}

	return hisee_scard_disconnect(0);
}
#pragma GCC diagnostic pop

/*
 * inse_release_cb: poweroff hisee when task exits.
 * HISEE_SUCCESS: power off successfuly.
 * HISEE_FAILURE: power off failed.
 */
static int inse_release_cb(const void *data)
{
	uart_printf_func("inse release cb called.\n");
	if (!data) {
		uart_printf_func("%s-%d\n", __func__, __LINE__);
		return HISEE_FAILURE;
	}

	return inse_disconnect(data);
}

/*
 * wait_cos_ready: wait for cos ready.
 * timeout: the time to wait.(ms)
 * HISEE_SUCCESS: cos ready. HISEE_FAILURE: cos not ready.
 */
static int wait_cos_ready(int timeout)
{
	int loopcount;

	if (timeout < 0) {
		uart_printf_func("%s:Invalid para, %d\n", __func__, timeout);
		return HISEE_FAILURE;
	}
	loopcount = timeout / HISEE_DELAY_TIME; /* every loop delay 10 ms. */
	while (hisee_vote_up() != HISEE_SUCCESS) {
		SRE_DelayMs(HISEE_DELAY_TIME);
		hm_yield();
		if (loopcount <= 0)
			return HISEE_FAILURE;
		loopcount--;
	}

	return HISEE_SUCCESS;
}

/*
 * wait_send_done: wait the send result of current ipc.
 * timeout:the time to wait.(cycle)
 * HISEE_SUCCESS: send successful HISEE_FAILURE: send failed.
 */
static int wait_send_done(int timeout)
{
	unsigned int val;

	if (timeout < 0) {
		uart_printf_func("%s:Invalid para, %d\n", __func__, timeout);
		return HISEE_FAILURE;
	}

	val = read32(HISEE_MBXRAM_IS_DONE_FLAG_PHYMEM_ADDR);
	if (((val & HISEE_VERSION_MASK) >> HISEE_VERSION_OFFSET) == NEW_HISEE) {
		while (timeout && ((val & DONE_FLAG_MASK) != HISEE_COPY_DONE)) {
			IPC_SLEEP(1);
			timeout--;
			val = read32(HISEE_MBXRAM_IS_DONE_FLAG_PHYMEM_ADDR);
		}
	} else { /* for old hisee */
		val = read32(SOC_IPC_MBX_MODE_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX));
		while (timeout && ((val & IPC_STATE_MASK) != IPC_STATE_ACK)) {
			IPC_SLEEP(1);
			timeout--;
			val = read32(SOC_IPC_MBX_MODE_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX));
		}
	}

	if (timeout == 0)
		return HISEE_FAILURE;

	return HISEE_SUCCESS;
}

static int prepare_for_ipc_send(unsigned char *p_cmd)
{
	int ret;

	if (!p_cmd) {
		uart_printf_func("Null Pointer when hisee_scard_transmit!\n");
		return HISEE_FAILURE;
	}

	uart_printf_func("HiSEE:begin send!\n");

	/* When hisee is powered on by TEE, we need to wait cos ready. */
	if (wait_cos_ready(WAIT_COS_READY_TIMEOUT) != HISEE_SUCCESS) {
		uart_printf_func("%s:Wait cos ready timeout!\n", __func__);
		return HISEE_FAILURE;
	}

	/* Wait for ipc seamphore */
	ret = pthread_mutex_lock(get_ipc_lock());
	if (ret != SRE_OK) {
		uart_printf_func("%s:Wait ipc seamphore failed: %x!\n", __func__, ret);
		return HISEE_FAILURE;
	}
	return HISEE_SUCCESS;
}


/*
 * hisee_ipc_send: Send data to hisee by ipc.
 * pipe_type: the type of pipe: SE_API or INSE_ENCRYPTION or the other.
 * p_cmd: the buffer to  send.
 * cmd_len: the size of the data to send.
 * HISEE_SUCCESS: successful HISEE_FAILURE: failed
 */
static int hisee_ipc_send(enum se_pipe_type pipe_type, unsigned char *p_cmd, unsigned int cmd_len)
{
	int ret = HISEE_FAILURE;
	unsigned int mbx_size, frame_size;
	unsigned int sent_size = 0;
	unsigned int size = cmd_len;
	struct ipc_msg msg;

	if (prepare_for_ipc_send(p_cmd) != HISEE_SUCCESS)
		return ret;

	mbx_size = mbx_sram_size_get(IPC_INSE_FASTMBOX);
	if (mbx_size == 0)
		goto exit;

	while (size) {
		frame_size = MIN(size, mbx_size);
		(void)memset_s(&msg, sizeof(struct ipc_msg), 0, sizeof(struct ipc_msg));

		msg.cmd_mix.cmd_src = OBJ_TEEOS;
		msg.cmd_mix.cmd_obj = OBJ_TEEOS;
		msg.cmd_mix.cmd = CMD_SETTING;
		msg.data[BUF_ID1] = frame_size;
		msg.data[BUF_ID2] = (size > frame_size) ? TRANS_CHAIN : TRANS_LAST;
		msg.data[BUF_ID3] = size;
		msg.data[BUF_ID4] = pipe_type;
		msg.mailbox_addr = (unsigned int)(uintptr_t)(p_cmd + sent_size); /* lint !e507 */
		msg.mailbox_size = frame_size;

		/* clear done flag */
		write32(HISEE_MBXRAM_IS_DONE_FLAG_PHYMEM_ADDR,
			(read32(HISEE_MBXRAM_IS_DONE_FLAG_PHYMEM_ADDR) & (~DONE_FLAG_MASK)));
		/* send the current frame. */
		ret = ipc_msg_send(OBJ_INSE, &msg);
		if (ret != HISEE_SUCCESS) {
			uart_printf_func("IPC send failed:0x%x\n", ret);
			goto exit;
		}

		/* wait send done. */
		if (wait_send_done(SCARD_CHAIN_TIMEOUT) == HISEE_FAILURE) {
			uart_printf_func("%s: send timeout\n", __func__);
			ret = HISEE_FAILURE;
			goto exit;
		}

		/* release mailbox */
		write32(SOC_IPC_MBX_SOURCE_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX), BIT(AP_SOURCE));

		/* Judge whether this session was aborted by hisee. */
		if (read32(SOC_IPC_MBX_DATA2_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX)) == TRANS_ABORT) {
			uart_printf_func("%s: Aborted by inse!\n", __func__);
			ret = HISEE_FAILURE;
			goto exit;
		}

		/* update the info of remain data. */
		sent_size += frame_size;
		size -= frame_size;
	}

	ret = HISEE_SUCCESS;
	uart_printf_func("HiSE:send done\n");
exit:
	/* Release the ipc seamphore */
	if (pthread_mutex_unlock(get_ipc_lock()) != SRE_OK)
		uart_printf_func("%s:Release ipc seamphore failed!\n", __func__);
	hisee_vote_down();
	return ret;
}

/*
 * inse_send: Called by INSE_ENCRYPTION pipe to send data to hisee.
 * p_cmd: the buffer to send.
 * cmd_len: the size of data to send.
 * HISEE_SUCCESS: successful HISEE_FAILURE: failed
 */
int inse_send(unsigned char *p_cmd, unsigned int cmd_len)
{
	return hisee_ipc_send(INSE_ENCRYPTION_PIPE_TYPE, p_cmd, cmd_len);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#ifdef MSP_EXT_TPDU
/*
 * hisee_tpdu_ipc_send: Send data to hisee by ipc.
 * pipe_type: the type of pipe: SE_API or INSE_ENCRYPTION
 * p_cmd: the buffer to  send.
 * cmd_len: the size of the data to send.
 * HISEE_SUCCESS: successful
 * HISEE_FAILURE: failed
 */
int hisee_tpdu_ipc_send(enum se_pipe_type pipe_type, unsigned char *cmd_data, unsigned int cmd_len)
{
	return hisee_ipc_send(pipe_type, cmd_data, cmd_len);
}
#endif

/*
 * scard_send: Called by SE_API pipe to send data to hisee.
 * reader_id: id for reader.
 * p_cmd: the buffer to  send.
 * cmd_len: the size of the data to send.
 * HISEE_SUCCESS: successful HISEE_FAILURE: failed
 */
int scard_send(int reader_id, unsigned char *p_cmd, unsigned int cmd_len)
{
#ifdef MSP_EXT_TPDU
	hisee_tpdu_set_ext_tag(EXT_TPDU_NO_TAG);
	if (cmd_len <= MAX_NORMAL_COMMAND_LENGTH)
		return hisee_ipc_send(SE_API_PIPE_TYPE, p_cmd, cmd_len);
	return hisee_extended_apdu_process(SE_API_PIPE_TYPE, p_cmd, cmd_len);
#else
	return hisee_ipc_send(SE_API_PIPE_TYPE, p_cmd, cmd_len);
#endif
}
#pragma GCC diagnostic pop

/*
 * receive_data: Receive data from mailbox.
 * p_rsp: The buffer to store data.
 * rsp_len: The size of buffer and also be the size of data as output.
 * HISEE_SUCCESS: successful HISEE_FAILURE: failed
 */
static int receive_data(unsigned char *p_rsp, unsigned int *rsp_len)
{
	char *data_addr = NULL;
	unsigned int rcv_len;
	unsigned int mbx_size;
	unsigned int cnt;

	/* get data addr & data size */
	data_addr = mbx_sram_addr_get(IPC_TEE_FASTMBOX);
	if (!data_addr) {
		uart_printf_func("IpcSramAddrNull\n");
		return HISEE_FAILURE;
	}

	mbx_size = mbx_sram_size_get(IPC_TEE_FASTMBOX);
	rcv_len = read32(SOC_IPC_MBX_DATA1_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX));
	if ((rcv_len > *rsp_len) || (rcv_len > mbx_size)) {
		uart_printf_func("rsp buffer is too short or data size is more than mailbox size, %d/%d/%d\n",
				 rcv_len, *rsp_len, mbx_size);
		return HISEE_FAILURE;
	}

	for (cnt = 0; cnt < rcv_len; cnt++)
		*((char *)p_rsp + cnt) = *((char *)data_addr + cnt);
	*rsp_len = rcv_len;

	return HISEE_SUCCESS;
}


/*
 * scard_get_status: Check whether there is a ipc message to be received.
 * SCARD_STATUS_RECEIVE_READY     : There is data to receive.
 * SCARD_STATUS_RECEIVE_NOT_READY : There is no data to recevie.
 */
int scard_get_status(void)
{
	unsigned int int_status;
	unsigned int value;
#ifdef MSP_EXT_TPDU
	unsigned int tpdu_response_status = hisee_tpdu_get_response_status();
	unsigned int ext_tpdu_tag = hisee_tpdu_get_ext_tag();

	if (tpdu_response_status == TPDU_RESPONSE_ABNORMAL &&
	   ext_tpdu_tag == EXT_TPDU_YES_TAG)
		return SCARD_STATUS_RECEIVE_READY;
#endif

	if (hisee_vote_up() != 0) {
		uart_printf_func("%s:cos not ready!\n", __func__);
		return SCARD_STATUS_RECEIVE_NOT_READY;
	}

	value = readl(HISEE_POWER_UP_ADDR);
	value &= BIT(HISEE_POWER_UP_BIT);
	if (value == 0) {
		uart_printf_func("HiseePowerDown\n");
		hisee_vote_down();
		return SCARD_STATUS_RECEIVE_NOT_READY;
	}
	int_status = read32(SOC_IPC_MBX_MODE_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX)) & 0xF0;

	hisee_vote_down();
	return (int_status == IPC_STATE_RECV) ? SCARD_STATUS_RECEIVE_READY : SCARD_STATUS_RECEIVE_NOT_READY;
}

/*
 * check_para_and_cos_ready : check parameters and cos status.
 * p_rsp : the parameter needed to check.
 * rsp_len : the parameter needed to check.
 * HISEE_SUCCESS: parameters are valid and cos is ready.
 * HISEE_FAILURE: otherwise.
 */
static int check_para_and_cos_ready(unsigned char *p_rsp, unsigned int *rsp_len)
{
	if (!p_rsp || !rsp_len) {
		uart_printf_func("%s: Invalid point %d len %d\n", __func__, p_rsp, rsp_len);
		return HISEE_FAILURE;
	}

	/* If cos is not ready, return error. */
	if (hisee_vote_up() != 0) {
		uart_printf_func("%s: cos is not ready!\n", __func__);
		return HISEE_FAILURE;
	}

	return HISEE_SUCCESS;
}
#ifdef MSP_EXT_TPDU
/*
 * hisee_tpdu_check_para_and_cos_ready : check parameters and cos status.
 *
 * p_rsp : the parameter needed to check.
 * rsp_len : the parameter needed to check.
 *
 * HISEE_SUCCESS: parameters are valid and cos is ready.
 * HISEE_FAILURE: otherwise.
 */
int hisee_tpdu_check_para_and_cos_ready(unsigned char *rsp_data, unsigned int *rsp_len)
{
	return check_para_and_cos_ready(rsp_data, rsp_len);
}
#endif

/*
 * get_nex_frame : send ipc to hisee to get the next frame.
 * size : the size of remain data.
 */
static void get_nex_frame(unsigned int size)
{
	int ret;
	unsigned int timeout = SCARD_CHAIN_TIMEOUT;
	unsigned int val;
	struct ipc_msg msg;

	if (size == 0) {
		uart_printf_func("%s:No next frame to recv!\n", __func__);
		return;
	}

	val = read32(HISEE_MBXRAM_IS_DONE_FLAG_PHYMEM_ADDR);
	if (((val & HISEE_VERSION_MASK) >> HISEE_VERSION_OFFSET) != NEW_HISEE)
		/* for old hisee, use ack to triger next frame. */
		return;

	ret = memset_s(&msg, sizeof(struct ipc_msg), 0, sizeof(struct ipc_msg));
	if (ret) {
		uart_printf_func("%s:memset_s error, ret = %d!\n", __func__, ret);
		return;
	}

	msg.cmd_mix.cmd_type = TEE_GET_APDU;
	msg.cmd_mix.cmd_src = OBJ_TEEOS;
	msg.cmd_mix.cmd_obj = OBJ_TEEOS;
	msg.cmd_mix.cmd = CMD_SETTING;
	msg.mailbox_addr = 0;
	msg.mailbox_size = 0;

	ret = ipc_msg_send(OBJ_INSE, &msg);
	if (ret != HISEE_SUCCESS) {
		uart_printf_func("%s-%d:%x\n", __func__, __LINE__, ret);
		return;
	}

	/* wait the ack. */
	while ((timeout) && (IPC_STATE_ACK !=
		(read32(SOC_IPC_MBX_MODE_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX)) & IPC_STATE_MASK))) {
		IPC_SLEEP(1);
		timeout--;
	}

	if (timeout == 0) {
		uart_printf_func("%s: wait ack timeout\n", __func__);
		return;
	}

	/* release mailbox */
	write32(SOC_IPC_MBX_SOURCE_ADDR(HISEE_IPC_BASE_ADDR, IPC_INSE_FASTMBOX), BIT(AP_SOURCE));
}

/*
 * wait_to_receive : wait for receive.
 * timeout : the time to wait(cycle).
 * HISEE_SUCCESS: There is data to receive.
 * HISEE_FAILURE: There isn't data to receive.
 */
static int wait_to_receive(int timeout)
{
	if (timeout < 0) {
		uart_printf_func("%s:Invalid para, %d\n", __func__, timeout);
		return HISEE_FAILURE;
	}

	while ((timeout) && (IPC_STATE_RECV !=
		(read32(SOC_IPC_MBX_MODE_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX)) & IPC_STATE_MASK))) {
		IPC_SLEEP(1);
		timeout--;
	}
	if (timeout == 0) {
		uart_printf_func("%s:wait receive timeout\n", __func__);
		return HISEE_FAILURE;
	}

	return HISEE_SUCCESS;
}

/*
 * get trans state for differnt platform
 * different platform for different operations
 */
static int get_trans_state(unsigned int *trans_state)
{
	/* 3660 ,710,970 not support huge data transmit */
#ifdef CONFIG_HISEE_IPC_SUPPORT_BIGDATA
	*trans_state = read32(SOC_IPC_MBX_DATA2_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX));
#else
	*trans_state = TRANS_LAST;
#endif
	if (*trans_state >= TRANS_MAX) {
		uart_printf_func("%s:Invalid transmit state %d\n", __func__, *trans_state);
		return HISEE_FAILURE;
	}
	return HISEE_SUCCESS;
}

/*
 * get total transt data length
 * HISEE_SUCCESS:success orther:failed
 */
static int get_trans_len(unsigned int *total_len, unsigned int trans_state, unsigned int rsp_size)
{
	/* Total data length to recv */
	if (trans_state > TRANS_LAST)
		*total_len = read32(SOC_IPC_MBX_DATA3_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX));
	else
		*total_len = read32(SOC_IPC_MBX_DATA1_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX));
	if (*total_len > rsp_size) {
		uart_printf_func("%s:ERROR:Rsp buffer %d data %d\n", __func__, rsp_size, *total_len);
		return HISEE_FAILURE;
	}
	return HISEE_SUCCESS;
}

/*
 * abort chain data and clear irq
 * different platform for different operations
 */
static void abort_chain_data(unsigned int trans_state)
{
	/* Abort chain data transmit */
#ifdef CONFIG_HISEE_IPC_SUPPORT_BIGDATA
	if (trans_state == TRANS_CHAIN)
		write32(SOC_IPC_MBX_DATA2_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX), TRANS_ABORT);
#else
	(void)trans_state;
#endif
	/* clear irq */
	write32(SOC_IPC_MBX_ICLR_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX), BIT(AP_SOURCE));
}

/*
 * Check if the parameter is empty.and get ipc lock.
 * HISEE_SUCCESS:success orther:failed
 */
static int prepare_for_ipc_receive(enum se_pipe_type pipe_type, unsigned char *p_rsp, unsigned int *rsp_len)
{
	int ret;

	if (check_para_and_cos_ready(p_rsp, rsp_len) != HISEE_SUCCESS)
		return HISEE_FAILURE;

	/* Wait for ipc seamphore */
	ret = pthread_mutex_lock(get_ipc_lock());
	if (ret != SRE_OK) {
		uart_printf_func("%s:Wait ipc seamphore failed: %x!\n", __func__, ret);
		return HISEE_FAILURE;
	}

	/*
	 * Judge whether the current ipc message is sent to current pipe.
	 * For old hisee, the ipc msg does not contain the pipe information,
	 * so do not jude pipe type for old hisee commuication that is SE_API_PIPE_TYPE.
	 */
	if ((pipe_type != SE_API_PIPE_TYPE) &&
		pipe_type != read32(SOC_IPC_MBX_DATA4_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX))) {
		uart_printf_func("%s: There is no data for pipe %x!\n", __func__, pipe_type);
		ret = HISEE_EMPTY;
		goto exit;
	}
	return HISEE_SUCCESS;
exit:
	/* Release ipc lock resource when no data is detected */
	if (pthread_mutex_unlock(get_ipc_lock()) != SRE_OK)
		uart_printf_func("%s:Release ipc seamphore failed!\n", __func__);
	uart_printf_func("HiSEE: recv ipc message fail!\n");
	return ret;
}


/*
 * hisee_ipc_receive: Receive data from hisee by ipc.
 * pipe_type: The type of pipe: SE_API or INSE_ENCRYPTION or the other.
 * p_rsp: The buffer to receive data.
 * rsp_len: The size of buffer and also be the size of data as output.
 * HISEE_SUCCESS: successful HISEE_EMPTY: No data for current pipe.
 * HISEE_FAILURE: failed
 */
static int hisee_ipc_receive(enum se_pipe_type pipe_type, unsigned char *p_rsp, unsigned int *rsp_len)
{
	int ret;
	unsigned int rcv_len = 0;
	unsigned int total_len, frame_len, rsp_size, mbx_size, trans_state;

	ret = prepare_for_ipc_receive(pipe_type, p_rsp, rsp_len);
	if (ret != HISEE_SUCCESS)
		return ret;

	uart_printf_func("HiSEE: Begin recv!\n");
	rsp_size = *rsp_len;
	mbx_size = mbx_sram_size_get(IPC_TEE_FASTMBOX);
	ret = get_trans_state(&trans_state);
	if (ret != HISEE_SUCCESS)
		goto error;
	ret = get_trans_len(&total_len, trans_state, rsp_size);
	if (ret != HISEE_SUCCESS)
		goto error;

	do {
		if (wait_to_receive(SCARD_CHAIN_TIMEOUT) == HISEE_FAILURE) {
			ret = HISEE_FAILURE;
			goto error;
		}

		frame_len = MIN(total_len, mbx_size);
		if (receive_data(&p_rsp[rcv_len], &frame_len) != HISEE_SUCCESS) {
			uart_printf_func("%s:receive data fail!\n", __func__);
			ret = HISEE_FAILURE;
			goto error;
		}
		if (total_len >= frame_len)
			total_len -= frame_len;
		rcv_len += frame_len;
		ret = get_trans_state(&trans_state);
		if (ret != HISEE_SUCCESS)
			goto error;
		/* clear irq to trigger next frame data */
		write32(SOC_IPC_MBX_ICLR_ADDR(HISEE_IPC_BASE_ADDR, IPC_TEE_FASTMBOX), BIT(AP_SOURCE));
		get_nex_frame(total_len);
	} while ((total_len > 0) && (trans_state == TRANS_CHAIN));

	*rsp_len = rcv_len;
	ret = HISEE_SUCCESS;
	goto exit;
error:
	abort_chain_data(trans_state);
exit:
	/* Release the ipc seamphore */
	if (pthread_mutex_unlock(get_ipc_lock()) != SRE_OK)
		uart_printf_func("%s:Release ipc seamphore failed!\n", __func__);
	uart_printf_func("HiSEE: recv done!\n");
	hisee_vote_down();
	return ret;
}
#ifdef MSP_EXT_TPDU
/*
 * hisee_ipc_receive: Receive data from hisee by ipc.
 * pipe_type: The type of pipe: SE_API or
 * INSE_ENCRYPTION or the other.
 * p_rsp: The buffer to receive data.
 * rsp_len: The size of buffer and also be the size of
 * data as output.
 *
 * HISEE_SUCCESS: successful
 * HISEE_EMPTY: No data for current pipe.
 * HISEE_FAILURE: failed
 */
int hisee_tpdu_ipc_receive(enum se_pipe_type pipe_type, unsigned char *rsp_data, unsigned int *rsp_len)
{
	return hisee_ipc_receive(pipe_type, rsp_data, rsp_len);
}
#endif

/*
 * inse_receive: Called by INSE_ENCRYPTION pipe to send data to hisee.
 * p_rsp: The buffer to receive data.
 * rsp_len: The size of the buffer and also be the size of data as output.
 */
int inse_receive(unsigned char *p_rsp, unsigned int *rsp_len)
{
	return hisee_ipc_receive(INSE_ENCRYPTION_PIPE_TYPE, p_rsp, rsp_len);
}

/*
 * scard_receive: Called by SE_API pipe to send data to hisee.
 * p_rsp: The buffer to receive data.
 * rsp_len: The size of the buffer and also be the size of data as output.
 */
int scard_receive(unsigned char *p_rsp, unsigned int *rsp_len)
{
#ifdef MSP_EXT_TPDU
	unsigned int tpdu_response_status = hisee_tpdu_get_response_status();
	unsigned int ext_tpdu_tag = hisee_tpdu_get_ext_tag();

	if (tpdu_response_status == TPDU_RESPONSE_ABNORMAL &&
	   ext_tpdu_tag == EXT_TPDU_YES_TAG) {
		hisee_tpdu_set_ext_tag(EXT_TPDU_NO_TAG);
		return hisee_tpdu_abnormal_receive_data(p_rsp, rsp_len);
	}
#endif
	return hisee_ipc_receive(SE_API_PIPE_TYPE, p_rsp, rsp_len);
}

int hisee_scard_support_mode(void)
{
	return SCARD_MODE_SYNC2;
}

