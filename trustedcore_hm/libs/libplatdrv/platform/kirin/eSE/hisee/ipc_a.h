/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos to hisee ipc driver.
 * Create: 2019/9/30
 */


#ifndef __IPC_A_H__
#define __IPC_A_H__
#include "soc_acpu_baseaddr_interface.h"
#include "soc_ipc_interface.h"

#define REG_UNLOCK_KEY           0x1ACCE551

/* ******************IPC SOURCE DEFINE****************** */
#ifdef CONFIG_HISEE_14_CHANNEL_IPC
#define AP_SOURCE                4  /* teeos ipc channel is independed */
#define INSE_SOURCE              7
#define MAX_MAILBOX_NUM          14
#else
#define AP_SOURCE                0  /* teeos and atf channel are the same */
#define INSE_SOURCE              4
#define MAX_MAILBOX_NUM          30
#endif

#define MAX_MAIL_SIZE            8
/* *******************ERROR NUM DEFINE******************* */
#define IM_OK                    0
#define IM_TIMEOUT_ERR           1
#define IM_ALLOC_ERR             2
#define IM_CREATE_ERR            3
#define IM_PARA_ERR              4
#define IM_FORMAT_ERR            5
#define IM_CONFLICT_ERR          6
#define IM_STATUS_ERR            7
#define IM_DEVICE_ERR            8
#define IM_NOACK_RET             127

/* *******************IPC MODE DEFINE******************* */
#define MBOX_STATE_MASK          0xF0
#define MBOX_IDLE_STAT           0x10
#define MBOX_SRC_STAT            0x20
#define MBOX_DST_STAT            0x40
#define MBOX_ACK_STAT            0x80

#define MBOX_NORMAL              0x08
#define MBOX_FAST                0x04
#define MBOX_MODE_MASK           0x03
#define MBOX_LINKMODE            0x02
#define MBOX_AUTOACK             0x01
#define MBOX_MANUACK             0x00
/* *******************MBOX SRAM DEFINE******************* */
#define HISEE_IPC_BASE_ADDR      SOC_ACPU_HISEE_IPC_BASE_ADDR
#define HISEE_MBOX_BASE_ADDR     SOC_ACPU_HISEE_MAILBOX_BASE_ADDR
#define MAILBOX_SRAM_BLOCK_SIZE  512
#define MAILBOX_SRAM_BLOCK       32U
#define MAILBOX_SRAM_TABLE_ADDR  \
	(HISEE_MBOX_BASE_ADDR + MAILBOX_SRAM_BLOCK_SIZE * MAILBOX_SRAM_BLOCK - 1 * MAILBOX_SRAM_BLOCK)

#define IPC_STATE_IDLE               (1 << 4)
#define IPC_STATE_RECV               (1 << 6)
#define IPC_STATE_ACK                (1 << 7)
#define IPC_STATE_MASK               0xF0

#define WAIT_COS_READY_TIMEOUT       3000


#define IPC_SLEEP(t)                          /* usleep(t) */

#ifndef BIT
#define BIT(n)                                (1 << (n))
#endif

#define CRC_RESULT_MASK                   0x0000FFFF /* The low 16 bits of ipc data7 register */
#define CRC_SIZE_MASK                     0xFFFF0000 /* The high 16 bits of ipc data7 register */

/* enum and struct define */
enum buf_id {
	BUF_ID0 = 0,
	BUF_ID1 = 1,
	BUF_ID2 = 2,
	BUF_ID3 = 3,
	BUF_ID4 = 4,
	BUF_ID5 = 5,
	BUF_ID6 = 6,
	BUF_ID7 = 7,
};

#ifdef CONFIG_HISEE_14_CHANNEL_IPC
enum block_id {
	MBOX_HISEE_ATF    = 3,           /* SRAM FLAG which is used for HISEE->ATF IPC */
	MBOX_HISEE_MODEM  = 7,           /* SRAM FLAG which is used for HISEE->MODEM IPC */
	MBOX_HISEE_HIFI   = 8,           /* SRAM FLAG which is used for HISEE->HIFI IPC */
	MBOX_HISEE_LPMCU  = 9,           /* SRAM FLAG which is used for LPMCU<->HISEE IPC */
	MBOX_ATF_HISEE    = 10,          /* SRAM FLAG which is used for ATF ->HISEE IPC */
	MBOX_HISEE_TEE    = 11,          /* SRAM FLAG which is used for TEE <->HISEE IPC */
	MBOX_HISEE_IOM7   = 12,          /* SRAM FLAG which is used for IOM7 <->HISEE IPC */
	MBOX_HISEE_ISP    = 13,          /* SRAM FLAG which is used for HIFI <->HISEE IPC */
	MAX_MBOX_FLAG     = 0xFF,        /* MAX FLAG */
};
#else
enum block_id {
	MBOX_HISEE_ATF    = 0,           /* SRAM FLAG which is used for HISEE->ATF IPC */
	MBOX_ATF_HISEE    = 13,          /* SRAM FLAG which is used for ATF ->HISEE IPC */
	MBOX_HISEE_LPMCU  = 20,          /* SRAM FLAG which is used for LPMCU<->HISEE IPC */
	MBOX_HISEE_TEE    = 16,          /* SRAM FLAG which is used for TEE <->HISEE IPC */
	MBOX_HISEE_HIFI   = 24,          /* SRAM FLAG which is used for HIFI <->HISEE IPC */
	MBOX_HISEE_MODEM  = 21,          /* SRAM FLAG which is used for MODEM<->HISEE IPC */
	MAX_MBOX_FLAG     = 0xFF,        /* MAX FLAG */
};
#endif

struct cmd_parse {
	unsigned char cmd_type;
	unsigned char cmd;
	unsigned char cmd_obj;
	unsigned char cmd_src;
	unsigned char cmd_para[4];      /* 4: num of cmd para */
};

struct ipc_msg {
	union {
		unsigned int data[MAX_MAIL_SIZE];
		struct cmd_parse cmd_mix;
	};
	unsigned char mailbox_id;
	unsigned int mailbox_addr;
	unsigned int mailbox_size;
	unsigned char dest_id;
	unsigned char mode;
};

/* ipc-irq-mailbox hard map */
struct ipc_hd_map {
	unsigned char mbx_id;
	unsigned int mbx_irq;
	unsigned int mbx_type;
};

union ipc_data {
	unsigned int data[MAX_MAIL_SIZE];
	struct cmd_parse cmd_mix;
};

/* funcs for external files */
unsigned int mbx_sram_size_get(unsigned char  mbx_id);
char *mbx_sram_addr_get(unsigned char mbx_id);
int ipc_send_msg(const struct ipc_msg *cfg);
int ipc_recv_msg(unsigned char mailbox, struct ipc_msg *cfg);
void ipc_dump_msg(unsigned char mailbox);
#endif /* __IPC_A_H__ */
