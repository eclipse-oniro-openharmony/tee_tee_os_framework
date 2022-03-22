/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#ifndef __MSG_SHA_DEF_H__
#define __MSG_SHA_DEF_H__

#include "msg_id.h"
/* follow msg_id.h definition */
#define GET_MSG_SID(a) ((a)&0xFFF)
#define GET_MSG_GID(a) (((a) >> 12) & 0x3)
#define MSG_TOTAL_IDS_NUM (MDRV_MSG_MID_TOTAL_NUM)

/* cmsg definition */
enum msg_cid {
    MSG_CID_UNUSED, /* 编号为0的空着不用 */
    MSG_CID_AP = 1,
    MSG_CID_TSP,
    MSG_CID_TVP,
    MSG_CID_LPMCU,
    MSG_CID_HIFI,
    MSG_CID_TEE,
    MSG_CORE_MAX,
};
#define MSG_MID_SHA_REG_MAGIC (0xD)
struct mid_unit_sha {
    unsigned int mid : 16;     /* reseved 2 bit; group id 2bit ;sub id 12 bit; */
    unsigned int cid : 4;      /* core id */
    unsigned int magic : 4;    /* id valid flag and magic */
    unsigned int reserved : 8; /* reseved 8 bit */
};

enum cmsg_type {
    CMSG_TYPE_PROTO = 1,
    CMSG_TYPE_SINGLE = 2, /* 单条消息 */
    CMSG_TYPE_SEGBEG = 3, /* 分段消息开始 */
    CMSG_TYPE_SEGMSG = 4, /* 分段消息中间 */
    CMSG_TYPE_SEGEND = 5, /* 分段消息结束 */
    CMSG_TYPE_LITE = 6,   /* 单条lite消息 */
};

struct cmsg_hdr {
    u8 type; /* cmsg_type */
    u8 rsv;
    u16 seq;   /* 跨核消息的计数，用于底层通道的检查 */
    u16 flags; /* 跨核消息的标记，目前还没有用到 */
    u16 len;   /* cmsg报文长度, 最大只能支持到65535 */
};

struct cmsg_lite_exthdr {
    u32 src;
    u32 dst;
};

/* follow mdrv_msg.h definition */
#define MSG_ERR_ESRCH (-3)             /* No such process */
#define MSG_ERR_EIO (-5)               /* Input/output error */
#define MSG_ERR_ENXIO (-6)             /* No such device or address */
#define MSG_ERR_EAGAIN (-11)           /* Resource temporarily unavailable */
#define MSG_ERR_ENOMEM (-12)           /* Cannot allocate memory */
#define MSG_ERR_EEXIST (-17)           /* File exists */
#define MSG_ERR_EINVAL (-22)           /* Invalid argument */
#define MSG_ERR_ECHRNG (-44)           /* Channel number out of range */
#define MSG_ERR_ETIME (-62)            /* Timer expired */
#define MSG_ERR_EPROTO (-71)           /* Protocol error */
#define MSG_ERR_EBADMSG (-74)          /* Bad message */
#define MSG_ERR_ENETUNREACH (-101)     /* Network is unreachable */
#define MSG_ERR_EHOSTUNREACH (-113)    /* No route to host */
#define MSG_ERR_ENOTRECOVERABLE (-131) /* State not recoverable */

/* * @brief 进行消息发送时，要求不要加时间戳，可能用户自己加了，或者为了性能就不要时间戳 */
#define __MSG_NO_TS 0x80u
/* * @brief 进行消息发送失败时，支持异步通知，尚未使用 */
#define __MSG_EDETECT (0x200u)

struct msg_flag {
    unsigned short mem_type : 3; /* 尚未使用 */
    unsigned short align : 1;    /* 尚未使用 */
    unsigned short dma : 1;      /* 尚未使用 */
    unsigned short free : 1;     /* 尚未使用 */
    unsigned short no_ts : 1;    /* 尚未使用 */
    unsigned short urgent : 1;
    unsigned short mem_reserve : 1;
    unsigned short outside : 1;  /* 尚未使用 */
    unsigned short reserved : 3; /* 尚未使用 */
    unsigned short version : 3;  /* 尚未使用 */
};

#define MSG_HEAD_SET_FLAG(a, f)                               \
    do {                                                      \
        ((struct msg_head *)(a))->flag = (unsigned short)(f); \
    } while (0)

#define MSG_HEAD_GET_FLAG(a) ((struct msg_head *)(a))->flag

#endif
