/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps module driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <sre_typedef.h>
#include <tee_log.h>
#include <securec.h>
#include <hieps_errno.h>
#include <hieps_ipc.h>
#include <hieps_cdrm_cmd.h>


/* store ChinaDRM message data. */
hieps_cdrm_msg_t g_hieps_cdrm_msg;

/*
 * @brief      : hieps_clear_cdrm_msg : clear the ChinaDRM message.
 */
void hieps_clear_cdrm_msg(void)
{
	(void)memset_s(&g_hieps_cdrm_msg, sizeof(hieps_cdrm_msg_t), 0, sizeof(hieps_cdrm_msg_t));
	g_hieps_cdrm_msg.flag = HIEPS_CDRM_MSG_DONE;
}

/*
 * @brief      : hieps_get_cdrm_msg : get the ChinaDRM message.
 *
 * @return     : ChinaDRM message data.
 */
hieps_cdrm_msg_t hieps_get_cdrm_msg(void)
{
	return g_hieps_cdrm_msg;
}

/*
 * @brief      : hieps_set_cdrm_msg : set the ChinaDRM message.
 *
 * @param[in]  : addr : the address of data.
 * @param[in]  : size : the size of data.
 */
static void hieps_set_cdrm_msg(uint32_t addr, uint32_t size)
{
	g_hieps_cdrm_msg.flag = HIEPS_CDRM_MSG_DOING;
	g_hieps_cdrm_msg.addr = addr;
	g_hieps_cdrm_msg.size = size;
}

/*
 * @brief      : hieps_send_cdrm_msg : send ChinaDRM message to hieps.
 *
 * @param[in]  : addr : the address of data.
 * @param[in]  : size : the size of data.
 *
 * @return     : HIEPS_OK: successfully, others: failed.
 */
uint32_t hieps_send_cdrm_msg(uint32_t addr, uint32_t size)
{
	uint32_t ret = HIEPS_ERROR;
	ipc_msg_t msg = { 0 };

	msg.data[0] = IPC_CMD_PACK(OBJ_AP0, OBJ_AP0, CMD_CDRM, IPC_CMD_VERSION);
	msg.data[1] = addr;
	msg.data[2] = size;

	ret = hieps_ipc_send(OBJ_HIEPS, &msg, SYNC_MODE);
	if (ret != HIEPS_OK)
		tloge("hieps cdrm:send ipc msg failed! ret=0x%x\n", ret);

	return ret;
}

/*
 * @brief      : hieps_cdrm_process : process ipc message for ChinaDRM.
 *
 * @param[in]  : msg : ipc message to process.
 *
 * @return     : HIEPS_OK: successfully, HIEPS_ERROR: failed.
 */
static int32_t hieps_cdrm_process(ipc_msg_t *msg)
{
	hieps_cdrm_msg_t cdrm_msg = { 0 };
	uint32_t addr = msg->data[1];
	uint32_t size = msg->data[2];

	cdrm_msg = hieps_get_cdrm_msg();
	if (cdrm_msg.flag == HIEPS_CDRM_MSG_DONE) {
		hieps_set_cdrm_msg(addr, size);
		return HIEPS_OK;
	} else {
		tloge("hieps:Last ChinaDRM message has not been processed!\n");
		return HIEPS_ERROR;
	}
}

/*
 * @brief      : hieps_cdrm_init : initialize ChinaDRM for hieps.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
int32_t hieps_cdrm_init(void)
{
	int32_t ret;

	hieps_clear_cdrm_msg();
	/* Register hieps ipc handler to process ChinaDRM message. */
	ret = hieps_ipc_msg_req_callback(OBJ_HIEPS, CMD_CDRM, hieps_cdrm_process);
	if (ret != HIEPS_OK)
		tloge("hieps cdrm:Register ipc callback failed: 0x%x\n", ret);

	return ret;
}
