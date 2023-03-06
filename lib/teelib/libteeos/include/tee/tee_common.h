/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef __TEE_COMMON_H_
#define __TEE_COMMON_H_

#include "tee_inner_uuid.h"

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * CMD ID Supported by Global Task
 */
enum global_service_cmd_id {
    GLOBAL_CMD_ID_INVALID                   = 0x0,  /* Global Task invalid cmd ID */
    GLOBAL_CMD_ID_BOOT_ACK                  = 0x1,  /* Global Task boot ack */
    GLOBAL_CMD_ID_OPEN_SESSION              = 0x2,  /* Global Task open Session */
    GLOBAL_CMD_ID_CLOSE_SESSION             = 0x3,  /* Global Task close Session */
    GLOBAL_CMD_ID_LOAD_SECURE_APP           = 0x4,  /* Global Task load dyn ta */
    GLOBAL_CMD_ID_NEED_LOAD_APP             = 0x5,  /* Global Task judge if need load ta */
    GLOBAL_CMD_ID_REGISTER_AGENT            = 0x6,  /* Global Task register agent */
    GLOBAL_CMD_ID_UNREGISTER_AGENT          = 0x7,  /* Global Task unregister agent */
    GLOBAL_CMD_ID_REGISTER_NOTIFY_MEMORY    = 0x8,  /* Global Task register notify memory */
    GLOBAL_CMD_ID_UNREGISTER_NOTIFY_MEMORY  = 0x9,  /* Global Task unregister notify memory */
    GLOBAL_CMD_ID_INIT_CONTENT_PATH         = 0xa,  /* Global Task init content path */
    GLOBAL_CMD_ID_TERMINATE_CONTENT_PATH    = 0xb,  /* Global Task terminate content path */
    GLOBAL_CMD_ID_ALLOC_EXCEPTION_MEM       = 0xc,  /* Global Task alloc exception memory */
    GLOBAL_CMD_ID_TEE_TIME                  = 0xd,  /* Global Task get tee secure time */
    GLOBAL_CMD_ID_TEE_INFO                  = 0xe,  /* Global Task tlogcat get tee info */
    GLOBAL_CMD_ID_REGISTER_LOG_MEM          = 0xf,  /* Global Task register LOG memory */
    GLOBAL_CMD_ID_KILL_TASK                 = 0x10, /* Global Task Kill task session */
    GLOBAL_CMD_ID_ADJUST_TIME               = 0x12, /* Global Task TIME adjust */
    GLOBAL_CMD_ID_SET_BUILD_VERSION         = 0x14, /* Global Task set the Android's build version */
    GLOBAL_CMD_ID_REGISTER_TTF_MEM          = 0x15, /* Global Task register TTF memory */
    GLOBAL_CMD_ID_GET_SESSION_SECURE_PARAMS = 0x16, /* Global Task get params */
    GLOBAL_CMD_ID_REGISTER_MAILBOX          = 0x17, /* Global Task register mailbox memory pool */
    GLOBAL_CMD_ID_REGISTER_UNUSUAL_TTF_MEM  = 0x18, /* Global Task register unusual TTF memory */
    GLOBAL_CMD_ID_DUMP_MEMINFO              = 0x1a, /* Global Task dump memory */
    GLOBAL_CMD_ID_SET_SERVE_CMD             = 0x1b, /* Global Task used to service no ca handle cmd */
    GLOBAL_CMD_ID_LATE_INIT                 = 0x20, /* Global Task for late init for permission service */
    GLOBAL_CMD_ID_GET_TEE_VERSION           = 0x22, /* Global Task get tee version */
    GLOBAL_CMD_ID_UPDATE_TA_CRL             = 0x23, /* Global Task update ta crl */
    GLOBAL_CMD_ID_REGISTER_RESMEM           = 0x24, /* Global Task register reserved memory */
#ifdef CONFIG_ENABLE_DUMP_SRV_SESS
    GLOBAL_CMD_ID_DUMP_SRV_SESS             = 0x25, /* Global Task dump service/session info */
#endif
    GLOBAL_CMD_ID_TRACE_ENABLE              = 0x26,
    GLOBAL_CMD_ID_UNKNOWN                   = 0x7FFFFFFE, /* *< Global Task ID not define */
    GLOBAL_CMD_ID_MAX                       = 0x7FFFFFFF  /* *< Global Task MAX ID not in use */
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof ((a)[0]))
#endif
typedef union {
    struct {
        uint8_t        msg_class;
        uint8_t        msg_flags;
        uint16_t    msg_id;
        uint32_t    msg_size;
    } __attribute__((packed)) send;

    struct {
        int64_t        ret_val;
        uint32_t    msg_size;
        uint32_t    reserve;
    } __attribute__((packed)) reply;
} hm_msg_header;

enum msg_class {
    MSG_HEADER_CLASS_PROCMGR,
    MSG_HEADER_CLASS_PATHMGR,
    MSG_HEADER_CLASS_MEMMGR,
    MSG_HEADER_CLASS_TAMGR,
    MSG_HEADER_CLASS_IRQMGR,
    MSG_HEADER_CLASS_IOMGR,
    MSG_HEADER_CLASS_ACMGR,
    MSG_HEADER_CLASS_TMRMGR,
    MSG_HEADER_CLASS_DRV_PWRMGR,
    MSG_HEADER_CLASS_ACQUIRE_RND,
    MSG_HEADER_CLASS_UPDATE_RND,
    MSG_HEADER_CLASS_RECV_RND,
};

#define MSG_ID_DRV_PWRMGR_SUSPEND_CPU 0x0001
#define MSG_ID_DRV_PWRMGR_RESUME_CPU 0x0002
#define MSG_ID_DRV_PWRMGR_SUSPEND_S4 0x0003
#define MSG_ID_DRV_PWRMGR_RESUME_S4 0x0004
#define MSG_ID_INVALID 0xffff

#endif
