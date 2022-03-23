/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu mailbox
 */

#include "npu_mailbox.h"

#include <errno.h>
#include <string.h>
#include <sre_sys.h> // for SRE_DelayMs;
#include <pthread.h>
#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "npu_common.h"
#include "npu_doorbell.h"
#include "npu_platform.h"
#include "npu_mailbox_utils.h"
#include "npu_semaphore.h"

static int npu_mailbox_send_message_check(struct npu_mailbox *mailbox,
                                          struct npu_mailbox_message *message_info, int *result)
{
	if (mailbox == NULL || message_info == NULL || result == NULL) {
		NPU_ERR("invalid input argument\n");
		return -1;
	}

	if (!mailbox->working) {
		NPU_ERR("mailbox not working\n");
		return -1;
	}

	if (message_info->message_length > DEVDRV_MAILBOX_PAYLOAD_LENGTH) {
		NPU_ERR("message length is too long\n");
		return -1;
	}
	return 0;
}

int npu_mailbox_message_send_trigger(struct npu_mailbox *mailbox,
                                     struct npu_mailbox_message *message)
{
	int ret;
	if (mailbox == NULL || message == NULL) {
		NPU_ERR("invalid input param null\n");
		return -1;
	}
	struct npu_platform_info *plat_info = NULL;

	NPU_DEBUG("npu_mailbox_message_send_trigger enter\n");
	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_ops failed\n");
		return -1;
	}

	if (mailbox->send_sram == NULL) {
		NPU_ERR("send_sram is null ,may be npu is not powered up now \n");
		return -1;
	}

	ret = DEVDRV_PLAT_GET_RES_MAILBOX_SEND(plat_info) (mailbox->send_sram,
		DEVDRV_MAILBOX_PAYLOAD_LENGTH, message->message_payload, message->message_length);
	if (ret != 0) {
		NPU_ERR("npu_mailbox_send failed\n");
		return ret;
	}

	message->is_sent = 1;
	return npu_write_doorbell_val(DOORBELL_RES_MAILBOX, DOORBELL_MAILBOX_MAX_SIZE, DOORBELL_MAILBOX_VALUE);
}

static void npu_delete_message(struct npu_mailbox_message *message)
{
	message->process_result = -1;
	if (message->abandon == DEVDRV_MAILBOX_RECYCLE_MESSAGE) {
		goto out;
	}

	message->abandon = DEVDRV_MAILBOX_RECYCLE_MESSAGE;

	return;

out:
	TEE_Free(message->message_payload);
	message->message_payload = NULL;
	TEE_Free(message);
	message = NULL;
}

static int npu_mailbox_message_create(struct npu_mailbox *mailbox,
                                      u8 *buf, u32 len,
                                      struct npu_mailbox_message **message_ptr)
{
	int i;
	struct npu_mailbox_message *message = NULL;
	if (mailbox == NULL ||
		buf == NULL ||
		len < sizeof(struct npu_mailbox_message_header) ||
		len > DEVDRV_MAILBOX_PAYLOAD_LENGTH) {
		NPU_ERR("input argument invalid\n");
		return -1;
	}

	message = (struct npu_mailbox_message *)TEE_Malloc(sizeof(struct npu_mailbox_message), 0);
	if (message == NULL) {
		NPU_ERR("kmalloc failed\n");
		return -ENOMEM;
	}

	message->message_payload = NULL;
	message->message_payload = TEE_Malloc(DEVDRV_MAILBOX_PAYLOAD_LENGTH, 0);
	if (message->message_payload == NULL) {
		TEE_Free(message);
		message = NULL;
		NPU_ERR("kmalloc message_payload failed\n");
		return -ENOMEM;
	}
	int ret;
	ret = memcpy_s(message->message_payload, len, buf, len);
	if (ret != 0) {
		TEE_Free(message);
		NPU_ERR("Failed to copy buf to message->message_payload\n");
		return -1;
	}
	for (i = len; i < DEVDRV_MAILBOX_PAYLOAD_LENGTH; i++) {
		message->message_payload[i] = 0;
	}
	message->message_length = DEVDRV_MAILBOX_PAYLOAD_LENGTH;
	message->process_result = 0;
	message->sync_type = DEVDRV_MAILBOX_SYNC;
	message->cmd_type = 0;
	message->message_index = 0;
	message->message_pid = 0;
	message->mailbox = mailbox;
	message->abandon = DEVDRV_MAILBOX_VALID_MESSAGE;
	*message_ptr = message;
	return 0;
}

static irqreturn_t npu_mailbox_ack_irq(int irq, const void *data)
{
	UNUSED(data);
	UNUSED(irq);
	NPU_INFO("irq = %d", irq);
	npu_sem_post(TS_MBX_SEM);
	return IRQ_HANDLED;
}

void npu_set_mailbox_base_vaddr(struct npu_dev_ctx *dev_ctx, u64 vaddr)
{
	dev_ctx->mailbox.send_sram = (u8 *)(uintptr_t)vaddr;
}

int npu_get_mailbox_base_vaddr(struct npu_dev_ctx *dev_ctx, u64 *vaddr)
{
	if (vaddr == NULL) {
		NPU_ERR("out param vaddr is null\n");
		return -1;
	}

	if (dev_ctx->mailbox.send_sram == NULL) {
		NPU_ERR("mailbox send_sram is null, maybe npu is not powered up now\n");
		return -1;
	}

	*vaddr = (u64)(uintptr_t)dev_ctx->mailbox.send_sram;

	return 0;
}

int npu_mailbox_init(int dev_id)
{
	int ret;
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_mailbox *mailbox = NULL;
	struct npu_platform_info *plat_info = NULL;

	if ((dev_id < 0) || (dev_id > NPU_DEV_NUM)) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	mailbox = &dev_ctx->mailbox;

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info\n");
		return -1;
	}

	if (mailbox == NULL) {
		NPU_ERR("input argument error\n");
		return -1;
	}
	// init
	INIT_LIST_HEAD(&mailbox->send_queue.list_header);

	// init send queue
	MUTEX_LOCK(mailbox);
	mailbox->send_queue.mailbox_type = DEVDRV_MAILBOX_SRAM;
	mailbox->send_queue.status = DEVDRV_MAILBOX_FREE;

	mailbox->send_sram = NULL;
	mailbox->receive_sram = NULL;
	MUTEX_UNLOCK(mailbox);

//	 register irq handler
	ret = request_irq(DEVDRV_PLAT_GET_MAILBOX_ACK_IRQ(plat_info), (irq_handler_t)npu_mailbox_ack_irq,
		IRQF_TRIGGER_NONE, "npu-ack", mailbox);
	if (ret != 0) {
		NPU_ERR("mailbox request_irq ack irq failed ret 0x%x\n", ret);
		return ret;
	}

	mailbox->working = 1;
	return ret;
}

/*
	if send_queue is free,send msg to ts directly,otherwise store msg to send queue
	preparing to send when the last mailbox message ts ack is comming
*/
int npu_mailbox_msg_send_async(struct npu_mailbox *mailbox,
                               struct npu_mailbox_message *message,
                               int *result)
{
	int ret;
	struct npu_mailbox_message_header *header = NULL;

	// check input para
	ret = npu_mailbox_send_message_check(mailbox, message, result);
	if (ret != 0) {
		NPU_ERR("create mailbox message faled\n");
		return ret;
	}
	// get mailbox message head
	header = (struct npu_mailbox_message_header *)message->message_payload;
	header->result = 0;
	header->valid = DEVDRV_MAILBOX_MESSAGE_VALID;

	message->process_result = 0;
	message->is_sent = 0;
	if (message->sync_type == DEVDRV_MAILBOX_SYNC) {
		message->message_type = DEVDRV_MAILBOX_SYNC_MESSAGE;
	} else {
		message->message_type = DEVDRV_MAILBOX_ASYNC_MESSAGE;
	}

	// protect common resource (mailbox->send_queue.list_header、mailbox->send_queue.status)
	// to avoid concurency between business thread and mbx_sending_thread
	MUTEX_LOCK(mailbox);

	// add msg to send_queue
	list_add_tail(&message->send_list_node, &mailbox->send_queue.list_header);

	if (mailbox->send_queue.status == DEVDRV_MAILBOX_FREE) {
		mailbox->send_queue.status = DEVDRV_MAILBOX_BUSY;
		(void)npu_mailbox_message_send_trigger(mailbox, message); // send message to ts
	}

	MUTEX_UNLOCK(mailbox);

	return 0;
}

static int npu_mailbox_message_send_ext(struct npu_mailbox *mailbox,
                                        struct npu_mailbox_message *message,
                                        int *result)
{
	int ret;
	struct npu_mailbox_message_header *header = NULL;

	NPU_DEBUG("enter\n");

	// check input para
	ret = npu_mailbox_send_message_check(mailbox, message, result);
	if (ret != 0) {
		NPU_ERR("create mailbox message faled\n");
		return ret;
	}

	// fill message
	header = (struct npu_mailbox_message_header *)message->message_payload;
	header->result = 0;
	header->valid = DEVDRV_MAILBOX_MESSAGE_VALID;

	message->process_result = 0;
	message->is_sent = 0;

	// send message
	MUTEX_LOCK(mbx_send); // protect send, avoid multithread problem
	ret = npu_mailbox_message_send_trigger(mailbox, message);
	if (ret != 0) {
		goto FAILED;
	}

	// hm not support timeout now,timeout must be ensured by ts
	// if ts down will cause wait indefinitely
	npu_sem_wait(TS_MBX_SEM);
	*result = message->process_result;
FAILED:
	MUTEX_UNLOCK(mbx_send);

	return ret;
}

int npu_mailbox_message_send_for_res(u8 dev_id, u8 *buf, u32 len, int *result)
{
	int ret;
	struct npu_mailbox_message *message = NULL;
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_mailbox *mailbox = NULL;

	if (dev_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	mailbox = &dev_ctx->mailbox;
	// create message
	ret = npu_mailbox_message_create(mailbox, buf, len, &message);
	if (ret != 0) {
		NPU_ERR("create mailbox message failed\n");
		return -1;
	}
	// send message
	ret = npu_mailbox_message_send_ext(mailbox, message, result);
	if (ret != 0) {
		NPU_ERR("devdrv_mailbox_message_send failed\n");
		ret = -1;
	} else  {
		ret = 0;
	}

	if (message != NULL) {
		if (message->message_payload != NULL) {
			TEE_Free(message->message_payload);
			message->message_payload = NULL;
		}
		TEE_Free(message);
		message = NULL;
	}

	return ret;
}


void npu_mailbox_recycle(struct npu_mailbox *mailbox)
{
	struct npu_mailbox_message *message = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	NPU_INFO("npu_mailbox_recycle enter");

	MUTEX_LOCK(mailbox);
	if (!list_empty_careful(&mailbox->send_queue.list_header)) {
		list_for_each_safe(pos, n, &mailbox->send_queue.list_header) {
			message = list_entry(pos, struct npu_mailbox_message, send_list_node);
			list_del(pos);
			npu_delete_message(message);
		}
	}
	MUTEX_UNLOCK(mailbox);
}

void npu_mailbox_exit(struct npu_mailbox *mailbox)
{
	struct npu_platform_info *plat_info = NULL;

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info\n");
		return;
	}

	if (mailbox == NULL) {
		NPU_ERR("input argument error\n");
		return;
	}

	// register irq handler
	free_irq(DEVDRV_PLAT_GET_MAILBOX_ACK_IRQ(plat_info), mailbox);
	mailbox->working = 0;
	npu_mailbox_recycle(mailbox);
}

void npu_mailbox_destroy(int dev_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_mailbox *mailbox = NULL;
	struct npu_platform_info *plat_info = NULL;

	if ((dev_id < 0) || (dev_id > NPU_DEV_NUM)) {
		NPU_ERR("device id is illegal\n");
		return;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id %d failed\n", dev_id);
		return;
	}

	mailbox = &dev_ctx->mailbox;
	if (mailbox == NULL) {
		NPU_ERR("npu devid %d mailbox argument error\n", dev_id);
		return;
	}

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info\n");
		return;
	}

	// register irq handler
	free_irq(DEVDRV_PLAT_GET_MAILBOX_ACK_IRQ(plat_info), mailbox);
	mailbox->working = 0;
}
