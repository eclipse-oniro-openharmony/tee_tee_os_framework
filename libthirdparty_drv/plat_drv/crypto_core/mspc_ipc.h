/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for msp core IPC module.
 * Author : w00371137
 * Create: 2019/12/05
 */

#ifndef __MSPC_IPC_H__
#define __MSPC_IPC_H__

#include <stdint.h>
#include <stdbool.h>

#define IPC_TEE_FASTMBOX        4
#define IPC_MSPC_FASTMBOX       11
#define IPC_ATF_ACK_MBXFIQ      353      /* ATF -- ACK */
#define IPC_TEE_ACK_MBXFIQ      354      /* TEE -- ACK */
#define IPC_ATF_MBXFIQ          355      /* ATF receive - mbox_int[3] */
#define IPC_TEE_MBXFIQ          356      /* TEE receive - mbox_int[4] */

#define MAX_MAIL_SIZE           8

enum {
    MSPC_ASYNC_MODE,
    MSPC_SYNC_MODE,
    MSPC_MAX_IPC_MODE
};

struct cmd_parse {
    uint8_t cmd_type;
    uint8_t cmd;
    uint8_t cmd_obj;
    uint8_t cmd_src;
    uint8_t cmd_para[4];
};

struct mspc_ipc_msg {
    union {
        uint32_t data[MAX_MAIL_SIZE];
        struct cmd_parse cmd_mix;
    };
    uint8_t   ipc_id;
    uint8_t   mailbox_id;
    uintptr_t mailbox_addr;
    uint32_t  mailbox_size;
    uint32_t  ipc_base;
    uint8_t   src_id;
    uint8_t   dest_id;
    uint8_t   mode;
};

enum mspc_ipc_data_index {
    MSPC_IPC_DATA0    = 0,
    MSPC_IPC_DATA1,
    MSPC_IPC_DATA2,
    MSPC_IPC_DATA3,
    MSPC_IPC_DATA4,
    MSPC_IPC_DATA5,
    MSPC_IPC_DATA6,
    MSPC_IPC_DATA7,
};

enum {
    OBJ_AP,             /* 0 */
    OBJ_LIT_CLUSTER,    /* 1 */
    OBJ_BIG_CLUSTER,    /* 2 */
    OBJ_GPU,            /* 3 */
    OBJ_DDR,            /* 4 */
    OBJ_ASP,            /* 5 */
    OBJ_HIFI,           /* 6 */
    OBJ_IOM3,           /* 7 */
    OBJ_LPM3,           /* 8 */
    OBJ_MODEM,          /* 9 */
    OBJ_SYS,            /* 10 */
    OBJ_HKADC,          /* 11 */
    OBJ_REGULATOR,      /* 12 */
    OBJ_CLK,            /* 13 */
    OBJ_TEMPERTURE,     /* 14 */
    OBJ_COUL,           /* 15 */
    OBJ_PSCI,           /* 16 */
    OBJ_TELEMNTN,       /* 17 */
    OBJ_MCA,            /* 18 */
    OBJ_MSPC,           /* 19 */ /* OBJ_INSE -> OBJ_MSPC */
    OBJ_TEST,           /* 20 */
    OBJ_TEEOS,          /* 21 */
    MAX_CMD_OBJ         /* 22 */
};

enum {
    CMD_ON,             /* 0 */
    CMD_OFF,            /* 1 */
    CMD_INQUIRY,        /* 2 */
    CMD_SETTING,        /* 3 */
    CMD_NOTIFY,         /* 4 */
    CMD_TEST,           /* 5 */
    CMD_NOBUSINESS,     /* 6 */
    MAX_CMD_MODE        /* 7 */
};

enum {
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
    /* 10 cmd_types are used for InSE only */
    TYPE_MSPC_A = 0x50,     /* 0x50 */
    TYPE_MSPC_B,            /* 0x51 */
    TYPE_MSPC_C,            /* 0x52 */
    TYPE_MSPC_D,            /* 0x53 */
    TYPE_MSPC_E,            /* 0x54 */
    TYPE_MSPC_F,            /* 0x55 */
    TYPE_MSPC_G,            /* 0x56 */
    TYPE_MSPC_H,            /* 0x57 */
    TYPE_MSPC_I,            /* 0x58 */
    TYPE_MSPC_TEST,         /* 0x59 */
    MAX_CMD_TYPE            /* 0x5A */
};

int32_t mspc_ipc_req_callback(uint32_t obj, uint32_t cmd,
                              int32_t (*func)(struct mspc_ipc_msg *));
int32_t mspc_ipc_get_mbx_ram(uint32_t mbx_id, uint32_t *size, uint32_t *addr);
int32_t mspc_send_ipc(uint32_t obj, struct mspc_ipc_msg *msg, uint32_t mode);
void mspc_ipc_irq_handler(uint32_t irq);
void mspc_ipc_irq_ctrl(bool enable);
int32_t mspc_ipc_init(void);
int32_t mspc_ipc_resume(void);
void mspc_mailbox_data_copy(uint8_t *dst, uint8_t *src, uint32_t size);

#endif /* __MSPC_IPC_H__ */
