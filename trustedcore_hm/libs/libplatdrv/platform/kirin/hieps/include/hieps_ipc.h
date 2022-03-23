/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for ipc module.
 * Create: 2019-01-31
 */


#ifndef __IPC_H__
#define __IPC_H__

#include <eps_ddr_layout_define.h>
#include <soc_eps_ipc_interface.h>
#include <soc_acpu_baseaddr_interface.h>

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#ifndef ARRY_SIZE
#define ARRY_SIZE(a)                (sizeof(a)/sizeof((a)[0]))
#endif

#define HIEPS_IPC_BASE_ADDR         (SOC_ACPU_EPS_IPC_BASE_ADDR)
#define IPC_MBX_DISTRIBUTION        (EPS_MBX_DISTRIBUTION_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))

#define AP0_SOURCE                  (3) /* bit3 */
#define AP1_SOURCE                  (4) /* bit4 */
#define HIEPS_SOURCE                (7) /* bit7 */
#define INVALID_SOURCE              (0)

#define IPC0_FROM_EPS               (3)
#define IPC1_FROM_EPS               (4)
#define IPC0_TO_EPS                 (10)
#define IPC1_TO_EPS                 (11)
#define IPC_NORMAL_MBX              (0xFF) /*defined for ACK */

#define MAX_MAILBOX_NUM             (14) /* HIEPS has 14 ipc. */

#define HIEPS_IPC0_FAST_IRQ         (454) /* Fast irq. */
#define HIEPS_IPC1_FAST_IRQ         (455) /* Fast irq. */
#define HIEPS_IPC0_NORMAL_IRQ       (456) /* ACK irq. */
#define HIEPS_IPC1_NORMAL_IRQ       (457) /* ACK irq. */

/*********************ERROR NUM DEFINE*********************/
#define IM_NOACK_RET                (127)

#define IS_ACK                      (1)
#define NOT_ACK                     (-1)
#define NONE                        (0)
/*********************IPC MODE DEFINE*********************/
#define MBOX_STATE_MASK             (0xF0)
#define MBOX_IDLE_STAT              (0x10)
#define MBOX_SRC_STAT               (0x20)
#define MBOX_DST_STAT               (0x40)
#define MBOX_ACK_STAT               (0x80)

#define MBOX_NORMAL                 (0x08)
#define MBOX_FAST                   (0x04)
#define MBOX_MODE_MASK              (0x03)
#define MBOX_LINKMODE               (0x02)
#define MBOX_AUTOACK                (0x01)
#define MBOX_MANUACK                (0x00)

#define MAX_MAIL_SIZE               (8) /* 8 data reg. */
#define MAX_IPC_CALLBACK_NUM        (5)

#define IPC_WAIT_IDLE_TIMEOUT       (2000)
#define IPC_WAIT_REQUEST_TIMEOUT    (20)

#define IPC_INIT_FINISH_FLAG        (0x55AAAA55)
#define REG_UNLOCK_KEY              (0x1ACCE551)

#define IPC_MBX_SPACE_INIT          (0xD38F2C76)
#define IPC_CMD_VERSION             (0x01)
#define IPC_CMD_PACK(src, obj, cmd, version)     (((src) << 24) | ((obj) << 16) | ((cmd) << 8) | (version))

/***************SEND MAIL MODE DEFINE*********************/
enum {
	SYNC_CMD = 0,
	ASYNC_CMD       /*the same as autoack*/
};
/********************SEND MODE DEFINE*********************/
typedef enum IPC_MODE {
	ASYNC_MODE,
	SYNC_MODE,
	MAX_IPC_MODE
} ipc_mode_t;

/************************CMD DEFINE***********************/
typedef enum CMD_OBJ {
	OBJ_AP0,                /*0*/
	OBJ_LIT_CLUSTER,        /*1*/
	OBJ_BIG_CLUSTER,        /*2*/
	OBJ_GPU,                /*3*/
	OBJ_DDR,                /*4*/
	OBJ_ASP,                /*5*/
	OBJ_HIFI,               /*6*/
	OBJ_IOM7,               /*7*/
	OBJ_LPM3,               /*8*/
	OBJ_MODEM,              /*9*/
	OBJ_SYS,                /*10*/
	OBJ_HKADC,              /*11*/
	OBJ_REGULATOR,          /*12*/
	OBJ_CLK,                /*13*/
	OBJ_TEMPERTURE,         /*14*/
	OBJ_COUL,               /*15*/
	OBJ_PSCI,               /*16*/
	OBJ_TELEMNTN,           /*17*/
	OBJ_MCA,                /*18*/
	OBJ_INSE,               /*19*/    /*add by InSE core*/
	OBJ_TEST,               /*20*/
	OBJ_AP1,                /*21*/
	OBJ_ISP,                /*22*/
	OBJ_HIEPS,              /*23*/
	MAX_CMD_OBJ             /*24*/
} cmd_obj_t;

typedef enum CMD_MODE {
	CMD_ON,                 /*0*/
	CMD_OFF,                /*1*/
	CMD_INQUIRY,            /*2*/
	CMD_SETTING,            /*3*/
	CMD_NOTIFY,             /*4*/
	CMD_TEST,               /*5*/
	CMD_NOBUSINESS,         /*6*/
	CMD_UPDATE_CLK,         /*7*/
	CMD_EXCEPTION,          /*8*/
	CMD_CDRM,               /*9*/
	CMD_POWER,               /*9*/
	MAX_CMD_MODE            /*10*/
} cmd_mode_t;

typedef enum CMD_TYPE {
	TYPE_RESERVED,          /*0*/
	TYPE_POWER,             /*1*/
	TYPE_CLK,               /*2*/
	TYPE_CORE,              /*3*/
	TYPE_CLUSTER,           /*4*/
	TYPE_SLEEP,             /*5*/
	TYPE_SR,                /*6*/
	TYPE_MODE,              /*7*/
	TYPE_UPLIMIT,           /*8*/
	TYPE_DNLIMIT,           /*9*/
	TYPE_FREQ,              /*10*/
	TYPE_T,                 /*11*/
	TYPE_VOLT,              /*12*/
	TYPE_RESET,             /*13*/
	TYPE_PWC,               /*14*/
	TYPE_TEST,              /*15*/
	TYPE_BIST_ON,           /*16*/
	TYPE_BIST_CMD,          /*17*/
	TYPE_BIST_ALGO,         /*18*/
	TYPE_BIST_OFF,          /*19*/
	/*reserve*/
	/*10 cmd_types are used for InSE only*/
	TYPE_INSE_A = 0x50,     /*0x50*/
	TYPE_INSE_B,            /*0x51*/
	TYPE_INSE_C,            /*0x52*/
	TYPE_INSE_D,            /*0x53*/
	TYPE_INSE_E,            /*0x54*/
	TYPE_INSE_F,            /*0x55*/
	TYPE_INSE_G,            /*0x56*/
	TYPE_INSE_H,            /*0x57*/
	TYPE_INSE_I,            /*0x58*/
	TYPE_INSE_TEST,         /*0x59*/
	/*reserve*/
	TYPE_EPS_CDRM,          /* 0x60*/
	MAX_CMD_TYPE            /*0x61*/
} cmd_type_t;

struct ipc_hd_map {
	uint32_t recv_mbx_id;
	uint32_t send_mbx_id;
	uint32_t mbx_irq;
	uint32_t mbx_type;
	uint32_t processor;
	uint32_t source;
};

struct cmd_parse {
	uint8_t cmd_version;
	uint8_t cmd;
	uint8_t cmd_obj;
	uint8_t cmd_src;
};

typedef struct ipc_msg {
	union {
		uint32_t data[MAX_MAIL_SIZE];
		struct cmd_parse cmd_mix;
	};
	uint8_t mailbox_id;
	uint32_t mailbox_addr;
	uint32_t mailbox_size;
	uint8_t dest_id;
	uint8_t mode;
} ipc_msg_t;

typedef int32_t (*IPCMSGCB)(ipc_msg_t *);

typedef struct {
	IPCMSGCB ipc_msg_cb;
	uint32_t      obj;
	uint32_t      cmd;
} ipc_cb_st;

typedef struct {
	uint32_t addr;
	uint32_t size;
} ipc_mbx_info_t;

/* The stuct to record the distribution of mailbox ddr.
 * The size of this struct cannot greater than 512B
 */
typedef struct {
	uint32_t flag;
	ipc_mbx_info_t ipc[MAX_MAILBOX_NUM];
} ipc_mbx_distribution_t;


/*****************************************************************************
  联合体定义
*****************************************************************************/
union ipc_data {
	uint32_t	data[MAX_MAIL_SIZE];
	struct cmd_parse cmd_mix;
};

/*===============================================================================
 *                                global objects                               *
===============================================================================*/


/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
void hieps_enable_ipc_irq(void);
void hieps_disable_ipc_irq(void);
int32_t hieps_ipc_init(void);
int32_t hieps_ipc_resume(void);
int32_t hieps_ipc_send(uint32_t obj, ipc_msg_t *msg, u32 mode);
int32_t hieps_ipc_msg_req_callback(uint32_t obj, u32 cmd, IPCMSGCB func);
#endif /* __IPC_H__ */
