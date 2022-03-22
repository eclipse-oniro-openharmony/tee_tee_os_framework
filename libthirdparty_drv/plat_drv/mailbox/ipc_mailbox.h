/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 *  Description: Secure OS SEC IPC mailbox device definition.
 *  Author: Guo Xiaodong
 *  Create: 2019-03-05
 */

#ifndef _IPC_MAILBOX_H_
#define _IPC_MAILBOX_H_

#include "tee_log.h"
#include "drv_module.h"
#include <hisi_boot.h>
#include <ipc.h>
#include <pthread.h>
#include <sre_hwi.h>
#include <sre_typedef.h>

#define IPC_PR_ERR(fmt, args...) tloge("[IPC]%s:" fmt "\n", __func__, ##args)
#define IPC_PR_WARN(fmt, args...) tlogw("[IPC]%s:" fmt "\n", __func__, ##args)
#define IPC_PR_INFO(fmt, args...) tlogi("[IPC]%s:" fmt "\n", __func__, ##args)
#define IPC_PR_DEBUG(fmt, args...) tlogd("[IPC]%s:" fmt "\n", __func__, ##args)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* mailbox interrupt number definition START */
#define AO_S_MBX6_IRQ 202
/* mailbox interrupt number definition END */

#define MAX_ECHO_NUM 16
#define MAX_MBOX_ID 31
#define MAX_IPC_SRC_ID_NUM 2
#define CHANNEL_TIMEOUT 1040
#define CHANNEL_UDELAY_TIME 40

#define IDLE_STATUS (1 << 4)
#define SRC_STATUS (1 << 5)
#define DEST_STATUS (1 << 6)
#define ACK_STATUS (1 << 7)
#define AUTO_ACK_CONFIG (1 << 0)
#define NORMAL_ACK_CONFIG (0 << 0)
#define IPC_MODE_MASK 0xF0

#define EINVAL 1
#define ETIMEOUT 2
#define EIPC_LOCK 3
#define ENOMEM 4
#define EIPCBUSY 5

#define IPCBITMASK(n) (1 << (n))
#define IPCMBxSOURCE(mdev) ((mdev) << 6)
#define IPCMBxDSET(mdev) (((mdev) << 6) + 0x04)
#define IPCMBxMODE(mdev) (((mdev) << 6) + 0x10)
#define IPCMBxIMASK(mdev) (((mdev) << 6) + 0x14)
#define IPCMBxICLR(mdev) (((mdev) << 6) + 0x18)
#define IPCMBxSEND(mdev) (((mdev) << 6) + 0x1C)
#define IPCMBxDATA(mdev, index) (((mdev) << 6) + 0x20 + ((index) << 2))
#define IPCLOCK() 0xA00
#define IPC_UNLOCK_KEY 0x1ACCE551

struct ipc_irq_desc {
	unsigned int mbx_irq;
	unsigned int ipc_type;
	unsigned int mbox_id;
	unsigned int mbox_src_id[MAX_IPC_SRC_ID_NUM];
	unsigned char module_tag[MAX_ECHO_NUM];

	void (*ipc_notifier[MAX_ECHO_NUM])(union ipc_data *mbx_msg);
};

struct ipc_send_lock {
	unsigned int ipc_type;
	unsigned int mbox_id;
	pthread_mutex_t mbox_lock;
};

unsigned int ipc_baseaddr[] = {
	SOC_ACPU_AO_IPC_S_BASE_ADDR, SOC_ACPU_IPC_BASE_ADDR,
};

struct ipc_irq_desc g_mbox_irq_table[] = {
	/* irq	ipc_id	mailbox_id	src_id	tag	notify */
	{AO_S_MBX6_IRQ, AO_S_IPC, AO_MBX6_TO_ACPU, {AO_S_ACPU, AO_S_ACPU}, {0},
		{NULL}}};

struct ipc_send_lock g_mbox_lock[] = {
	/* ipc_type	mbox_id		pthread_lock */
	{AO_S_IPC, AO_MBX6_TO_ACPU, PTHREAD_MUTEX_INITIALIZER},
	{AO_S_IPC, AO_MBX1_TO_IOMCU, PTHREAD_MUTEX_INITIALIZER},
	{PERI_S_IPC, PERI_MBX21_TO_IVP, PTHREAD_MUTEX_INITIALIZER},
	{PERI_S_IPC, PERI_MBX29_TO_LPM3, PTHREAD_MUTEX_INITIALIZER},
	};

extern UINT32 SRE_SwMsleep(UINT32 uwMsecs);

#endif /* _IPC_MAILBOX_H_ */
