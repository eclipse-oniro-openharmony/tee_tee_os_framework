/*
 *  Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 *  Description: Secure OS SEC IPC Interface.
 *  Author: Guo Xiaodong
 *  Create: 2019-07-08
 */

#ifndef _IPC_H_
#define _IPC_H_

#include <soc_acpu_baseaddr_interface.h>

#define MAX_IPC_DATA_LEN	8

#define CMD_LEN_OF_DATA	4

/*
 * ipc module tag definition START
 */
enum ao_module_tag {
	TEST_CMD_001		= 0x1,
	TEST_CMD_002		= 0x2,
	TAG_THP		= 0x3A,
	TAG_AI_SVC		= 0x3F,
	MAX_SRC_TAG		= 0xFF,
};

/* ipc module tag definition END */

/*
 * ipc base_addr definition START
 */
enum ipc_type {
	AO_S_IPC = 0,
	PERI_S_IPC = 1,
	MAX_IPC_TYPE,
};
/* ipc base_addr definition END */

/*
 * ipc mailbox channel definition START
 */
enum ao_s_ipc_mbox_id {
	AO_MBX1_TO_IOMCU = 1,
	AO_MBX6_TO_ACPU = 6,
};

enum peri_s_ipc_mbox_id {
	PERI_MBX21_TO_IVP  = 21,
	PERI_MBX29_TO_LPM3 = 29, /* Used for seplat. */
};
/* ipc mailbox channel definition  END */

/*
 * ipc CORE ID definition START
 */
enum peri_s_ipc_core_id {
	PERI_S_AP_L,
	PERI_S_AP_B,
	PERI_S_IOMCU,
	PERI_S_LPMCU,
	PERI_S_ASP,
	PERI_S_MODEM_A9,
	PERI_S_IVP,
	PERI_S_ISP,
	PERI_S_MODEM_F,
};

enum ao_s_ipc_core_id {
	AO_S_IOMCU,
	AO_S_LPMCU,
	AO_S_ACPU,
	AO_S_ASP,
	AO_S_MODEM,
	AO_S_RSV,	/* reserved */
	AO_S_ISP,
	AO_S_MODEM_F,
};
/* ipc CORE ID definition END */

/* cmd_src & cmd_obj make up the unique Module TAG */
struct cmd_parse {
	unsigned char cmd_src;
	unsigned char cmd_obj;
	unsigned char cmd;
	unsigned char cmd_type;
	unsigned char cmd_para[CMD_LEN_OF_DATA];
};

union ipc_data {
	unsigned int data[MAX_IPC_DATA_LEN];
	struct cmd_parse cmd_mix;
};

struct ipc_msg {
	unsigned int ipc_id;
	unsigned int mbox_id;
	unsigned int src_id;
	unsigned int dest_id;
	unsigned int msg_len;
	union ipc_data *ipc_data;
};

int ipc_sync_send(const struct ipc_msg *msg, union ipc_data *ack_buffer,
	unsigned int ack_len);

int ipc_async_send(const struct ipc_msg *msg);

/* sec ipc interrupt callback register, must be invoked in initialization time */
int ipc_recv_notifier_register(unsigned int ipc_id, unsigned int mbox_id,
	unsigned char module_tag, const void *notifier);

/* sec ipc interrupt callback register, must be invoked in uninitialization time */
int ipc_recv_notifier_unregister(unsigned int ipc_id, unsigned int mbox_id,
	unsigned char module_tag);

int ipc_mbx_status_query(unsigned int ipc_id, unsigned int mbox_id);

#endif /* _IPC_H_ */

