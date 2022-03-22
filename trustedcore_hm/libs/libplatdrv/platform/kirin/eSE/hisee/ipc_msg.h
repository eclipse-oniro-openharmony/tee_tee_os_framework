/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos to hisee ipc driver.
 * Create: 2019/9/30
 */

#ifndef __IPC_MSG_H__
#define __IPC_MSG_H__

#include "ipc_a.h"
#include "pthread.h"

/* ************IPC & INSEIPC MAILBOX DEFINE*************** */
#ifdef CONFIG_HISEE_14_CHANNEL_IPC
#define IPC_AP_FASTMBOX             3            /* INSE --> ATF -mbox3 */
#define IPC_TEE_FASTMBOX            4            /* INSE --> TEE -mbox4 */
#define IPC_INSE_FASTMBOX           11           /* TEE --> INSE -mbox11 */

#define IPC_ACK_MBXFIQ              353          /* ATF -- ACK */
#define IPC_TEE_ACK_MBXFIQ          354          /* TEE -- ACK */
#define IPC_ATF_MBXFIQ              355          /* ATF receive - mbox_int[3] */
#define IPC_TEE_MBXFIQ              356          /* TEE receive - mbox_int[4] */
#else
#define IPC_AP_FASTMBOX             0            /* INSE --> ATF -mbox0 */
#define IPC_TEE_FASTMBOX            3            /* INSE --> TEE -mbox3 */
#define IPC_INSE_FASTMBOX           16           /* TEE --> INSE -mbox16 */

#define IPC_ACK_MBXFIQ              353          /* ATF -- ACK */
#define IPC_ATF_MBXFIQ              354          /* ATF receive -mbox0 irq */
#define IPC_TEE_MBXFIQ              357          /* TEE receive -mbox3 gic[4] */
#endif
#define IPC_INSE_NORMBOX            0xFF

#define MAX_IPC_CALLBACK_NUM        4             /* InSE register callback function number */



#define IPC_AP_NORMBOX              0xFF

#define ARRY_SIZE(a)               (sizeof(a) / sizeof((a)[0]))

/* *************SEND MAIL MODE DEFINE******************* */
enum {
	SYNC_CMD = 0,
	ASYNC_CMD       /* the same as autoack */
};
/* ******************SEND MODE DEFINE******************* */
enum ipc_mode_t {
	ASYNC_MODE,
	SYNC_MODE,
	MAX_IPC_MODE
};

/* **********************CMD DEFINE********************* */
enum cmd_obj {
	OBJ_AP,                 /* 0 */
	OBJ_LIT_CLUSTER,        /* 1 */
	OBJ_BIG_CLUSTER,        /* 2 */
	OBJ_GPU,                /* 3 */
	OBJ_DDR,                /* 4 */
	OBJ_ASP,                /* 5 */
	OBJ_HIFI,               /* 6 */
	OBJ_IOM3,               /* 7 */
	OBJ_LPM3,               /* 8 */
	OBJ_MODEM,              /* 9 */
	OBJ_SYS,                /* 10 */
	OBJ_HKADC,              /* 11 */
	OBJ_REGULATOR,          /* 12 */
	OBJ_CLK,                /* 13 */
	OBJ_TEMPERTURE,         /* 14 */
	OBJ_COUL,               /* 15 */
	OBJ_PSCI,               /* 16 */
	OBJ_TELEMNTN,           /* 17 */
	OBJ_MCA,                /* 18 */
	OBJ_INSE,               /* 19 */    /* add by InSE core */
	OBJ_TEST,               /* 20 */
	OBJ_TEEOS,              /* 21 */
	MAX_CMD_OBJ             /* 22 */
};

enum cmd_mode {
	CMD_ON,                 /* 0 */
	CMD_OFF,                /* 1 */
	CMD_INQUIRY,            /* 2 */
	CMD_SETTING,            /* 3 */
	CMD_NOTIFY,             /* 4 */
	CMD_TEST,               /* 5 */
	CMD_NOBUSINESS,         /* 6 */
	MAX_CMD_MODE            /* 7 */
};

enum cmd_type {
	TYPE_RESERVED,          /* 0 */
	TYPE_POWER,             /* 1 */
	TYPE_CLK,               /* 2 */
	TYPE_CORE,              /* 3 */
	TYPE_CLUSTER,           /* 4 */
	TYPE_SLEEP,             /* 5 */
	TYPE_SR,                /* 6 */
	TYPE_MODE,              /* 7 */
	TYPE_UPLIMIT,           /* 8 */
	TYPE_DNLIMIT,           /* 9 */
	TYPE_FREQ,              /* 10 */
	TYPE_T,                 /* 11 */
	TYPE_VOLT,              /* 12 */
	TYPE_RESET,             /* 13 */
	TYPE_PWC,               /* 14 */
	TYPE_TEST,              /* 15 */
	TYPE_BIST_ON,           /* 16 */
	TYPE_BIST_CMD,          /* 17 */
	TYPE_BIST_ALGO,         /* 18 */
	TYPE_BIST_OFF,          /* 19 */
	/* reserve */
	/* 10 cmd_types are used for InSE only */
	TYPE_INSE_A = 0x50,     /* 0x50 */
	TYPE_INSE_B,            /* 0x51 */
	TYPE_INSE_C,            /* 0x52 */
	TYPE_INSE_D,            /* 0x53 */
	TYPE_INSE_E,            /* 0x54 */
	TYPE_INSE_F,            /* 0x55 */
	TYPE_INSE_G,            /* 0x56 */
	TYPE_INSE_H,            /* 0x57 */
	TYPE_INSE_I,            /* 0x58 */
	TYPE_INSE_TEST,         /* 0x59 */
	/* reserve */
	MAX_CMD_TYPE            /* 0x5A */
};

/* InSE_CMD_TYPE cmd_type_t:0x50~0x5A */

typedef int (*IPCMSGCB)(struct ipc_msg *);

struct ipc_cb_st {
	IPCMSGCB ipc_msg_cb;
	unsigned int obj;
	unsigned int cmd;
};

int ipc_msg_init(void);
unsigned int ipc_msg_mbx_size_get(unsigned int processor_id);
int ipc_msg_send(unsigned int processor_id, struct ipc_msg *msg);
int ipc_msg_req_callback(unsigned int obj, unsigned int cmd, int (*func)(struct ipc_msg *));
int ipc_msg_put_callback(unsigned int obj, unsigned int cmd);
void ipc_msg_interrupt(unsigned int irq_nr);
pthread_mutex_t *get_ipc_lock(void);
pthread_mutex_t *get_vote_lock(void);
#endif /* __IPC_MSG_H__ */
