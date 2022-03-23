#ifndef __SENSORHUB_IPC_H__
#define __SENSORHUB_IPC_H__
 

//IPC_S Reg: 0x40218F000~0x40218FFFF
#define REG_IPC_BASE                  (0xFA898000)
//register offset
#define REG_MBOX_SOURCE_OFFSET(m)     (((m) << 6))
#define REG_MBOX_DEST_OFFSET(m)       (((m) << 6) + 0x04)
#define REG_MBOX_DCLEAR_OFFSET(m)     (((m) << 6) + 0x08)
#define REG_MBOX_DSTATUS_OFFSET(m)    (((m) << 6) + 0x0C)
#define REG_MBOX_MODE_OFFSET(m)       (((m) << 6) + 0x10)
#define REG_MBOX_IMASK_OFFSET(m)      (((m) << 6) + 0x14)
#define REG_MBOX_ICLR_OFFSET(m)       (((m) << 6) + 0x18)
#define REG_MBOX_SEND_OFFSET(m)       (((m) << 6) + 0x1C)
#define REG_MBOX_DATA_OFFSET(m, d)    (((m) << 6) + 0x20 + ((d) * 4))
#define REG_CPU_IMST_OFFSET(m)        (((m) << 3))
#define REG_IPC_LOCK_OFFSET           (0xA00)
#define IPC_UNLOCK_VALUE              (0x1ACCE551)
#define MBOX_MODE_NOT_AUTOACK         (0x0)
//mbox status
#define REG_IPC_STATUS_IDLE           (0x10)
#define REG_IPC_STATUS_ACK            (1 << 7)
//
#define IPC_DATA_REG_WIDTH            (4)
#define IPC_DATA_REG_NUM              (8)
#define MAX_SENSORHUB_MODEL_BLKS           (8)
#define MAX_SENSORHUB_INPUT_NUM            (4)
#define MAX_SENSORHUB_OUTPUT_NUM           (4)
//
#define INTR_AO_IPC_S_MBOX6           (202)

/*CPU ID分配：
每bit对应1个CPU，如下
00000001：IOMCU
00000010：LPMCU
00000100：ACPU
00001000：ASP
00010000：Modem
00100000：reserved
01000000：ISP
10000000：reserved*/
enum mbox_src_id {
    IPC_MBOX_SRC_IOMCU   = (1),
    IPC_MBOX_SRC_LPMCU   = (1<<1),
    IPC_MBOX_SRC_ACPU    = (1<<2),
    IPC_MBOX_SRC_ASP     = (1<<3),
    IPC_MBOX_SRC_MODEM   = (1<<4)
};
/*快速邮箱分配：
mbox0~3：IOMCU
mbox4~5：LPMCU
mbox6：  ACPU
mbox7：  ASP
mbox8：  Modem
mbox9：  reserved
mbox10： ISP
mbox11~12： IOMCU
mbox13： reserved
mbox14~15：公用普通邮箱*/
enum acpu_mbox_id {
    IOMCU_MBOX0 = 0,
    IOMCU_MBOX1,
    IOMCU_MBOX2,
    IOMCU_MBOX3,
    IOMCU_MBOX4 = 11,
    IOMCU_MBOX5,
};

enum SENSORHUB_mbox_id {
    ACPU_MBOX0 = 6,
};

//cmd
enum sensorhub_ipc_cmd {
    SENSORHUB_IPC_SEND_DATA,
    SENSORHUB_IPC_QUERY_ACK,
    SENSORHUB_IPC_QUERY_DATA,
    SENSORHUB_IPC_DCRYPT,
};

enum SensorhubModelCmd {
    SUB_CMD_SENSORHUB_LOAD_MODEL = 0x20,
    SUB_CMD_SENSORHUB_UNLOAD_MODEL,
    SUB_CMD_SENSORHUB_RUN_MODEL,
    SUB_CMD_SENSORHUB_QUERY_ACK,
};


//ipc packet
enum core_type{
    CORE_AP,
    CORE_MODEM,
    CORE_M7_INTERNAL,
    CORE_TEE,
    CORE_END
};

typedef struct {
    UINT8 tag;
    UINT8 cmd;
    UINT8 resp: 1;   /*value CMD_RESP means need resp, CMD_NO_RESP means need not resp*/
    UINT8 rsv: 3;
    UINT8 core: 4;
    UINT8 partial_order;
    UINT16 tranid;
    UINT16 length;
} pkt_header_t;

typedef struct {
    UINT8 tag;
    UINT8 partial_order;
    //u16 padding;
} pkt_part_header_t;

enum senhub_ipc_err {
    ERR_NONE = 0,
    ERR_MBOX_ERR,
    ERR_INVALID_CMD,
    ERR_INVALID_POINTER,
    ERR_INVALID_MSG_LENGTH,
    ERR_TIMEOUT,

    ERR_INVALID_NUM = 0xFF,      //invalid index
    ERR_INVALID_ACK = 0x1000,    //return to TA
};

typedef struct {
    UINT32 safefd;
    UINT32 modelsize;
    UINT32 ionsize;
} msg_decrypt ;

typedef struct {
    pkt_header_t pkt_header;//head for tiny
    UINT32 tiny_cmd; //cmd for tiny
} msg_header_t;

typedef struct
{
    uint32_t buf_type:8;
    uint32_t data_size:24;
    uint32_t data_addr;
}tqm_data_t;

typedef struct
{
    uint32_t uid:24;
    uint32_t blk_cnt:8;
    uint32_t load_context;
    tqm_data_t model_blks[1];
}ai_svc_load_model_t;

typedef struct {
    msg_header_t msg_h;
    ai_svc_load_model_t model_context;
}ipc_load_model_t;

#endif
