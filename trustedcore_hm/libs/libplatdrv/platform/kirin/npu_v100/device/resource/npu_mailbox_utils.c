/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:aboat pthread
 */

#include "npu_mailbox_utils.h"

#include <errno.h>
#include <string.h>
#include <sre_sys.h> // for SRE_DelayMs;
#include <pthread.h>
#include "drv_log.h"
#include "tee_mem_mgmt_api.h"
#include "npu_mailbox.h"
#include "npu_common.h"

static pthread_cond_t	s_mbx_cond;
static pthread_condattr_t	s_mbx_cond_attr;
static pthread_mutex_t	s_mbx_mutex;
static pthread_t mbx_sending_thread;

extern int npu_mailbox_message_send_trigger(struct npu_mailbox *mailbox,
                                            struct npu_mailbox_message *message);

void npu_mailbox_notifier_init()
{
	(void)pthread_mutex_init(&s_mbx_mutex, NULL);
	s_mbx_cond_attr.__attr = 0;
	(void)pthread_cond_init(&s_mbx_cond, &s_mbx_cond_attr);
}

void npu_mailbox_notifier_deinit()
{
	pthread_cond_destroy(&s_mbx_cond);
	pthread_condattr_destroy(&s_mbx_cond_attr);
	pthread_mutex_destroy(&s_mbx_mutex);
}

void npu_mailbox_msg_sending_wait()
{
	(void)pthread_mutex_lock(&s_mbx_mutex);
	(void)pthread_cond_wait(&s_mbx_cond, &s_mbx_mutex);
	(void)pthread_mutex_unlock(&s_mbx_mutex);
}

void npu_mailbox_sending_thread_wake_up()
{
	(void)pthread_mutex_lock(&s_mbx_mutex);
	(void)pthread_cond_broadcast(&s_mbx_cond);
	(void)pthread_mutex_unlock(&s_mbx_mutex);
}

/*
mailbox 消息发送流程
1、先将msg_node插入mailbox 发送队列中
2、判断发送队列的状态，如果空闲的话，将payload拷贝到mailbox sendsram中,
并写doorbell对应bit（127）通知TS，到步骤3.如果不空闲的话，到步骤3
3、判断当前msg的sync_type，如果是同步类型DEVDRV_MAILBOX_SYNC的话，调用
同步发送接口，等待信号量有效才继续往下走，信号量在TS ack中断响应函数里置为有效，
在每次msg创建的时候初始化为0
4、ts 回复mailbox之后，当前msg交互完成，释放msg内存块，中间会释放msg中的信号量
成员
*/
/* mailbox ts ack消息中断处理流程
1、判断mailbox->send_queue邮箱发送是否为空，如果为空直接返回，非空进入步骤2
2、取出发送队列的第一条msg
3、将该msg从发送队列send_queue摘除
4、将send_queue.status置为忙状态，防止msg在HIAI TA线程中被重复发送通知到TS
5、判断send_queue是否还有下一条消息，若有则将payload拷贝到mailbox sendsram中,
并写doorbell通知ts，若无，则将发送队列置位空闲状态，方便下次HIAI TA线程直接发送
消息给TS
6、判断msg是否是同步消息，如果是的话，up信号量，唤醒还在等待该msg ack的HIAT TA
mailbox发送线程

总结：每次最多只能发送一条消息，只有在等待上一条消息的ack已经到来之后才会
真正发送下一条消息给ts，在上一条消息还没收到ack之前，上一条发送mailbox的
发送线程会被阻塞，对于多线程下各自申请stream触发mailbox的情况，不同线程的
mailbox消息都会缓存到全局资源send_queue中，ack来之后换新对应的线程即可
但是hm是否能够这样支持呢?

hm 适配
hm有平台的特殊性，我们的目的是为了和TS正确的通信，保证TS在消费完上一条msg之后，
acpu才能写msg，防止消息被覆盖，所以只要驱动内部能够保证上面的要求被满足即可。
该方案就通过中断+发送队列实现即可，具体描述如下：
1、判断发送队列释放空闲，若空闲，发送mailbox给TS,HIAI TA系统调用直接返回
若发送队列被占用，HIAI TA系统调用直接返回，等待上一条中断ack之后，再发送

hm中TA和TA之间通信时通过消息队列，即使HIAI TA中创建多个线程来调用platdrv的服务
接口，在platdrv这个特殊TA也是串行处理的

中断在hm中本质上是一个线程

多个TA要做到消息同步需要通过sem_open接口实现，遵循libc接口，但hm在底层做了适配
（pthread 也是如此）
*/
static void* mbx_thread_func(void *param)
{
	UNUSED(param);
	struct npu_mailbox *mailbox = NULL;
	struct npu_mailbox_message *next_msg = NULL;
	struct npu_mailbox_message *message = NULL;
	struct npu_dev_ctx *dev_ctx = NULL;
	u8 dev_id = 0;

	dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(dev_ctx == NULL, NULL, "get device context by device id failed.\n");

	mailbox = &dev_ctx->mailbox;

	// for first mbx
	npu_mailbox_msg_sending_wait();

	while (1) {
		MUTEX_LOCK(mailbox);
		/* HIAI TA can not send msg directly now, after DEVDRV_MAILBOX_BUSY status */
		mailbox->send_queue.status = DEVDRV_MAILBOX_BUSY;

		if (list_empty_careful(&mailbox->send_queue.list_header)) {
			// wait here for ts mailbox ack
			NPU_WARN("mailbox->send_queue.list_header is empty, exception case");

			// to ensure the outer can send msg alone,
			// so this sending thread can be waked up when tscpu mailbox ack comming
			mailbox->send_queue.status = DEVDRV_MAILBOX_FREE; // no more msg in the mailbox sending queue
			npu_mailbox_msg_sending_wait();
		}

		// the first message has been handled completely,free it
		message = list_first_entry(&mailbox->send_queue.list_header, struct npu_mailbox_message,
			send_list_node);
		if (message != NULL) {
			list_del(&message->send_list_node);
			if (message->message_payload != NULL) {
				TEE_Free(message->message_payload);
				message->message_payload = NULL;
			}
			TEE_Free(message);
			message = NULL;
		}

		//sending message if sending queue is not empty
		if (!list_empty_careful(&mailbox->send_queue.list_header)) {
			next_msg = list_first_entry(&mailbox->send_queue.list_header,
				struct npu_mailbox_message, send_list_node);
			if (next_msg == NULL) {
				NPU_ERR("message passed from mailbox sending queue was null,terrible world");
				MUTEX_UNLOCK(mailbox);
				return NULL;
			}

			npu_mailbox_message_send_trigger(mailbox, next_msg);
		} else {
			// if there is no message node in the sending queue,
			mailbox->send_queue.status = DEVDRV_MAILBOX_FREE; // no more msg in the mailbox sending queue
		}

		// release lock to allow business thread insert mailbox msg to send_queue
		MUTEX_UNLOCK(mailbox);
		npu_mailbox_msg_sending_wait(); // wait here for ts mailbox ack
	}

	return NULL;
}

// create mbx sending thread to send mbx task getting from maibox sending queue
int npu_create_mbx_send_thread()
{
	pthread_attr_t attr;
	int error;

	error = pthread_attr_init(&attr);
	if (error) {
		NPU_ERR("mbx pthread attr init failed. error=%d", error);
		return error;
	}

	error = pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	if (error) {
		(void)pthread_attr_destroy(&attr);
		NPU_ERR("pthread attr setstacksize failed. error=%d", error);
		return error;
	}

	error = pthread_create(&mbx_sending_thread, &attr, mbx_thread_func, NULL);
	if (error) {
		NPU_ERR("pthread create failed. error=%d", error);
		(void)pthread_attr_destroy(&attr);
		return error;
	}

	error = pthread_attr_destroy(&attr);
	if (error) {
		NPU_ERR("pthread attr destroy failed. error=%d", error);
	}

	return error;
}

int npu_mbx_send_thread_join()
{
	int ret = pthread_join(mbx_sending_thread, NULL);
	if (ret) {
		NPU_DEBUG("pthread join failed. ret=%d", ret);
	}
	return ret;
}
