/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _BSP_EICC_H
#define _BSP_EICC_H

#include <osl_balong.h>

/**
 * @brief eicc句柄类型，用于屏蔽不同平台差异
 */
typedef unsigned eicc_chn_t;

/**
 * @brief eicc句柄类型无效值，应该使用此值对eicc_chn_t初始化
 */
#define EICC_CHN_INVAILD_HDL (0xFFFFFFFFU)

/** @brief 错误码：当前资源不足，请重试 */
#define EICC_ERR_EAGAIN (-11)

/**
 * @brief eicc通道号，用于打开通道时的标识 eicc_chn_attr_t.chnid
 */
enum eicc_chn_id {
    /* LPM3<-->AP */
    EICC_CHN_SEND_LPM2AP_MDRV_MSG = 0x00,
    EICC_CHN_RECV_LPM2AP_MDRV_MSG = 0x01,
    EICC_CHN_SEND_AP2LPM_MDRV_MSG = 0x02,
    EICC_CHN_RECV_AP2LPM_MDRV_MSG = 0x03,
    /* LPM3<-->TEEOS */
    EICC_CHN_SEND_LPM2TEE_MDRV_MSG = 0x04,
    EICC_CHN_RECV_LPM2TEE_MDRV_MSG = 0x05,
    EICC_CHN_SEND_TEE2LPM_MDRV_MSG = 0x06,
    EICC_CHN_RECV_TEE2LPM_MDRV_MSG = 0x07,

    /* TSP<-->LPM3 */
    EICC_CHN_SEND_TSP2LPM_MDRV_MSG = 0x10,
    EICC_CHN_RECV_TSP2LPM_MDRV_MSG = 0x11,
    EICC_CHN_SEND_LPM2TSP_MDRV_MSG = 0x12,
    EICC_CHN_RECV_LPM2TSP_MDRV_MSG = 0x13,
    /* TSP<-->HIFI */
    EICC_CHN_SEND_TSP2HIFI_MDRV_MSG = 0x14,
    EICC_CHN_RECV_TSP2HIFI_MDRV_MSG = 0x15,
    EICC_CHN_SEND_HIFI2TSP_MDRV_MSG = 0x16,
    EICC_CHN_RECV_HIFI2TSP_MDRV_MSG = 0x17,
    /* TSP<-->AP */
    EICC_CHN_SEND_TSP2AP_MDRV_MSG = 0x18,
    EICC_CHN_RECV_TSP2AP_MDRV_MSG = 0x19,
    EICC_CHN_SEND_AP2TSP_MDRV_MSG = 0x1A,
    EICC_CHN_RECV_AP2TSP_MDRV_MSG = 0x1B,
    /* TSP<-->TEEOS */
    EICC_CHN_SEND_TSP2TEE_MDRV_MSG = 0x1C,
    EICC_CHN_RECV_TSP2TEE_MDRV_MSG = 0x1D,
    EICC_CHN_SEND_TEE2TSP_MDRV_MSG = 0x1E,
    EICC_CHN_RECV_TEE2TSP_MDRV_MSG = 0x1F,
    /* TSP<-->TVP */
    EICC_CHN_SEND_TSP2TVP_MDRV_MSG = 0x20,
    EICC_CHN_RECV_TSP2TVP_MDRV_MSG = 0x21,
    EICC_CHN_SEND_TVP2TSP_MDRV_MSG = 0x22,
    EICC_CHN_RECV_TVP2TSP_MDRV_MSG = 0x23,

    /* TSP<-->AP */
    EICC_CHN_SEND_TSP2AP_MDRVRFILE = 0x24,
    EICC_CHN_RECV_TSP2AP_MDRVRFILE = 0x25,
    EICC_CHN_SEND_AP2TSP_MDRVRFILE = 0x26,
    EICC_CHN_RECV_AP2TSP_MDRVRFILE = 0x27,

	/* TSP<-->AP */
    EICC_CHN_SEND_TSP2AP_MDRVNV = 0x28,
    EICC_CHN_RECV_TSP2AP_MDRVNV = 0x29,
    EICC_CHN_SEND_AP2TSP_MDRVNV = 0x2A,
    EICC_CHN_RECV_AP2TSP_MDRVNV = 0x2B,

    EICC_CHN_SEND_DMA_MDRVMAA0 = 0x40,
    EICC_CHN_SEND_DMA_MDRVMAA1 = 0x42,
    EICC_CHN_SEND_DMA_MDRVMAA2 = 0x44,
    EICC_CHN_SEND_DMA_MDRVMAA3 = 0x46,

    EICC_CHN_SEND_DMA_MDRVPMSR = 0x48,

    /* eicc chn for phy */
    EICC_CHN_SEND_TSP2TVP_PHY0 = 0x80,
    EICC_CHN_RECV_TSP2TVP_PHY0 = 0x81,
    EICC_CHN_SEND_TSP2TVP_PHY1 = 0x82,
    EICC_CHN_RECV_TSP2TVP_PHY1 = 0x83,
    EICC_CHN_SEND_TSP2TVP_PHY2 = 0x84,
    EICC_CHN_RECV_TSP2TVP_PHY2 = 0x85,
    EICC_CHN_SEND_TSP2TVP_PHY3 = 0x86,
    EICC_CHN_RECV_TSP2TVP_PHY3 = 0x87,

    EICC_CHN_SEND_TVP2TSP_PHY0 = 0x88,
    EICC_CHN_RECV_TVP2TSP_PHY0 = 0x89,
    EICC_CHN_SEND_TVP2TSP_PHY1 = 0x8A,
    EICC_CHN_RECV_TVP2TSP_PHY1 = 0x8B,
    EICC_CHN_SEND_TVP2TSP_PHY2 = 0x8C,
    EICC_CHN_RECV_TVP2TSP_PHY2 = 0x8D,
    EICC_CHN_SEND_TVP2TSP_PHY3 = 0x8E,
    EICC_CHN_RECV_TVP2TSP_PHY3 = 0x8F,

    EICC_CHN_SEND_TSP2TVP_PHY4 = 0x90,
    EICC_CHN_RECV_TSP2TVP_PHY4 = 0x91,
    EICC_CHN_SEND_TSP2TVP_PHY5 = 0x92,
    EICC_CHN_RECV_TSP2TVP_PHY5 = 0x93,

    EICC_CHN_SEND_TVP2TSP_PHY4 = 0x98,
    EICC_CHN_RECV_TVP2TSP_PHY4 = 0x99,
    EICC_CHN_SEND_TVP2TSP_PHY5 = 0x9A,
    EICC_CHN_RECV_TVP2TSP_PHY5 = 0x9B,

    EICC_CHN_SEND_DMA_PS0 = 0x140,
    EICC_CHN_SEND_DMA_PS1 = 0x142,
    EICC_CHN_SEND_DMA_PS2 = 0x144,
    EICC_CHN_SEND_DMA_PS3 = 0x146,
    EICC_CHN_SEND_DMA_PS4 = 0x148,
    EICC_CHN_SEND_DMA_PS5 = 0x14A,
    EICC_CHN_SEND_DMA_PS6 = 0x14C,
    EICC_CHN_SEND_DMA_PS7 = 0x14E,

    /* eicc chn for test */
    EICC_CHN_SEND_TSP2TVP_MDRV_LLT = 0xFFFF0000,
    EICC_CHN_RECV_TSP2TVP_MDRV_LLT = 0xFFFF0001,
    EICC_CHN_SEND_TVP2TSP_MDRV_LLT = 0xFFFF0002,
    EICC_CHN_RECV_TVP2TSP_MDRV_LLT = 0xFFFF0003,

    EICC_CHN_SEND_TSP2AP_MDRV_LLT = 0xFFFF0010,
    EICC_CHN_RECV_TSP2AP_MDRV_LLT = 0xFFFF0011,
    EICC_CHN_SEND_AP2TSP_MDRV_LLT = 0xFFFF0012,
    EICC_CHN_RECV_AP2TSP_MDRV_LLT = 0xFFFF0013,

    EICC_CHN_INVAILD = 0xFFFFFFFFUL
};

/**
 * @brief eicc发送通道类型，用于打开通道时eicc_chn_attr_t.type
 */
#define EICC_CHN_TYPE_SEND 0x0
/**
 * @brief eicc接收通道类型，用于打开通道时eicc_chn_attr_t.type
 */
#define EICC_CHN_TYPE_RECV 0x1
/**
 * @brief eicc无效通道类型，用于打开通道时eicc_chn_attr_t.type
 */
#define EICC_CHN_TYPE_INVAILD 0xFFFFFFFFUL

/**
 * @brief eicc回调事件类型
 */
typedef enum {
    EICC_EVENT_DATA_ARRV,
    EICC_EVENT_SEND_DONE,
    EICC_EVENT_SEND_FLOWUP,
    EICC_EVENT_SEND_FLOWDN,
    EICC_EVENT_INVAILD,
} eicc_event;
/**
 * @brief eicc回调事件额外参数
 */
typedef union {
    struct {
        unsigned chnid;
        eicc_chn_t chn_hdl;
    } data_arrv; /* used for give information for event EICC_EVENT_DATA_ARRV */
} eicc_eventinfo;
/**
 * @brief eicc回调
 * @attention
 * <ul><li>此回调直接执行在中断上下文</li></ul>
 * @param[in]  event, 此次回调的事件类型
 * @param[in]  cbk_arg, 用户私有参数，此参数来自于open通道时用户传入
 * @param[in]  info, 此次回调所带的额外信息
 *
 * @retval 0,回调正确处理。
 * @retval 非0,回调未正确处理。
 *
 * @see mdrv_eicc_chn_open
 */
typedef int (*eicc_cbk)(eicc_event event, void *cbk_arg, const eicc_eventinfo *info);

/** @brief 默认情况下, 数据到达，接收方总是有通知的，该标志可以关闭该通知 */
#define EICC_ATTR_FLAGS_NOARRVEVENT (1U << 0)
/** @brief 设置该标记的通道，DPM低功耗时不管理(这种通道必须是DMA通道) */
#define EICC_ATTR_FLAGS_DPMSRIGNORE (1U << 4)
/** @brief 设置该标记的通道，低功耗管理在特定级别(需要硬件资源支持，使用该标记请与开发者确认) */
#define EICC_ATTR_FLAGS_DSSCTRLSR (1U << 31)
/**
 * @brief 用户打开通道时的输入参数
 * @attention
 * <ul><li>该结构体在使用前,必须使用eicc_chn_attr_init初始化</li></ul>
 * @see mdrv_eicc_chn_attr_init mdrv_eicc_chn_open
 */
typedef struct {
    unsigned chnid;    /**< 通道的id定义, 在attr_init后用户填写 */
    unsigned type;     /**< 通道收发属性，例如EICC_CHN_TYPE_SEND ,在attr_init后用户填写 */
    unsigned pa;       /**< ringbuf物理地址，硬件有对齐要求 8Bytes, 在attr_init后用户填写 */
    void *va;          /**< ringbuf虚拟地址,在attr_init后用户填写 */
    unsigned size;     /**< ringbuf大小，硬件有对齐要求 128Bytes,在attr_init后用户填写 */
    eicc_cbk cbk;      /**< eicc事件发生时的回调函数, 在attr_init后用户填写*/
    void *cbk_arg;     /**< 回调时，透传的用户私有数据，用户需要保证cbk_arg的生命周期,在attr_init后用户填写 */
    unsigned flags;    /**< 一些标志，比如唤醒，报中断等, 不清楚用处的在attr_init后不要操作 */
    unsigned int_cmsk; /**< 通道的中断绑定特性(平台相关)，不清楚用处的在attr_init后不要操作 */
    unsigned int_prio; /**< 通道的中断优先级(平台相关)，不清楚用处的在attr_init后不要操作 */
} eicc_chn_attr_t;


typedef struct {
    unsigned cnt;
    struct {
        void *buf;
        unsigned len;
    } datablk[0];
} eicc_blk_desc_t;

typedef struct {
    unsigned cnt;
    struct {
        void *buf;
        unsigned len;
    } datablk[2];
} eicc_blkx2_desc_t;

typedef struct {
    unsigned cnt;
    struct {
        void *buf;
        unsigned len;
    } datablk[3];
} eicc_blkx3_desc_t;

#define EICC_SEND_FLAGS_NOARRVNOTIFY (1UL << 0)
#define EICC_SEND_FLAGS_NODONENOTIFY (1UL << 1)

#define EICC_RECV_FLAGS_DATAPEEK (1UL << 0)

#define EICC_IOCTL_CHN_NXTPKT_INF 0x40000002
#define EICC_IOCTL_CHN_PACKET_SKIP 0x40000003
#define EICC_IOCTL_CHN_CAPSET_INF 0x40000004
#define EICC_IOCTL_CHN_STATUS_INF 0x40000005

typedef struct {
    u32 len;
    u32 pkthdl;
} ioctl_nxtpkt;

struct eicc_chn_status
{
    u32 busy;
};

int bsp_eicc_init(void);
/************************************************************************
 * 函 数 名  : bsp_eicc_chn_attr_init
 * 功能描述  : pattr用于描述打开通道的各种参数，该函数用于实现将pattr设置为默认值
 * 输入参数  :
 *            pattr: eicc通道属性描述
 * 输出参数  : 无
 * 返 回 值  :  0          操作成功。
 *             其他        操作失败。
 **************************************************************************/
int bsp_eicc_chn_attr_init(eicc_chn_attr_t *attr);

/************************************************************************
 * 函 数 名  : bsp_eicc_chn_open
 * 功能描述  : 根据pattr的描述，打开通道，通道必须打开之后才能进行数据收发
 *             需要先调用bsp_eicc_chn_attr_init对pattr初始化，pattr必须设置的字段参考pattr介绍
 * 输入参数  :
 *            pattr: eicc通道属性
 * 输出参数  :
 *            pchn_hdl:  eicc通道句柄，用于调用其他函数
 * 返 回 值  :  0          操作成功。
 *             其他        操作失败。
 **************************************************************************/
int bsp_eicc_chn_open(eicc_chn_t *pchn_hdl, eicc_chn_attr_t *attr);

/************************************************************************
 * 函 数 名 : bsp_eicc_chn_send
 * 功能描述  : 将一段buf直接发送到目的端
 * 输入参数  :
 *            chn_hdl: eicc通道句柄，由open通道时得到
 *            buf: 要发送的数据地址
 *            len: 要发送的数据长度
 *            flags: EICC_SEND_FLAGS，不了解的填0
 * 输出参数  :
 *            无
 * 返 回 值 :  成功返回实际发送长度，失败返回负值。
 **************************************************************************/
int bsp_eicc_chn_send(eicc_chn_t chn_hdl, void *buf, unsigned len, u32 flags);

/************************************************************************
 * 函 数 名 : bsp_eicc_chn_blks_send
 * 功能描述  : 将多段buf组合直接发送到目的端
 * 输入参数  :
 *            chn_hdl: eicc通道句柄，由open通道时得到
 *            blkdesc: 要发送的数据地址,长度等信息
 *            flags: EICC_SEND_FLAGS，不了解的填0
 * 输出参数  :
 *            无
 * 返 回 值 :  成功返回实际发送长度，失败返回负值。
 **************************************************************************/
int bsp_eicc_chn_blks_send(eicc_chn_t chn_hdl, eicc_blk_desc_t *blkdesc, u32 flags);

/************************************************************************
 * 函 数 名 : bsp_eicc_chn_recv
 * 功能描述  : 接收数据
 * 输入参数  :
 *            chn_hdl: eicc通道句柄，由open通道时得到
 *            buf: 用于接收数据的buf
 *            len: 用于接收数据的buf的大小
 *            flags: EICC_RECV_FLAGS，不了解的填0
 * 输出参数  :
 *            无
 * 返 回 值 :  成功实际接收数据长度(若没有数据，返回0)，失败返回负值(比如参数错误等)。
 **************************************************************************/
int bsp_eicc_chn_recv(eicc_chn_t chn_hdl, void *buf, unsigned len, u32 flags);

/************************************************************************
 * 函 数 名 : bsp_eicc_chn_ioctl
 * 功能描述  : arg根据req是输入或者输出
 * 输入参数  :
 *            chn_hdl: eicc通道句柄，由open通道时得到
 *            req: 请求命令字 EICC_IOCTL_CHN*
 *            arg: 请求命令字对应的输入参数
 *            size: arg的大小
 * 输出参数  :
 *            arg: 请求命令字对应的输出参数
 * 返 回 值 :  成功返回0，失败返回负值。
 **************************************************************************/
int bsp_eicc_chn_ioctl(eicc_chn_t chn_hdl, unsigned req, void *arg, u32 size);

int bsp_eicc_suspend(void);
int bsp_eicc_resume(void);
#endif /*  __BSP_EICC_H__ */
