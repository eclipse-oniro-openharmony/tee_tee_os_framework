/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 */
#ifndef __BSP_ICC_H__
#define __BSP_ICC_H__

#ifdef __cplusplus /* __cplusplus */
extern "C"
{
#endif /* __cplusplus */
#include <osl_balong.h>

#define ICC_CHAN_NUM_MAX      (32)

#define ICC_BUSY              (0x03 | NOTIFY_STOP_MASK)
#define ICC_OK                (0)
#define ICC_ERR               (-1)

#ifndef __ASSEMBLY__

/* CPU ID 分配 */
enum CPU_ID
{
	ICC_CPU_MIN = 0,
	ICC_CPU_APP = 0,
	ICC_CPU_MODEM = 1,
	ICC_CPU_MAX
};

/* 错误码定义 */
enum ICC_ERR_NO {
	ICC_CHN_INIT_FAIL = (0x80000000 + (0 << 16)),
	ICC_MALLOC_CHANNEL_FAIL,
	ICC_MALLOC_VECTOR_FAIL,
	ICC_CREATE_TASK_FAIL,
	ICC_DEBUG_INIT_FAIL,
	ICC_CREATE_SEM_FAIL,
	ICC_REGISTER_INT_FAIL,
	ICC_INVALID_PARA,
	ICC_WAIT_SEM_TIMEOUT,
	ICC_SEND_ERR,
	ICC_RECV_ERR,
	ICC_REGISTER_CB_FAIL,
	ICC_REGISTER_DPM_FAIL,
	ICC_MALLOC_MEM_FAIL,
	ICC_NULL_PTR,
	ICC_INIT_ADDR_TOO_BIG,
	ICC_INIT_SKIP

};

/* 通道id分配 */
enum ICC_S_CHN_ID {
	ICC_CHN_ACORE_CCORE_MIN = 17, /* modem reset : 通道开始标志 */
	ICC_CHN_SEC_IFC  = 17,        /* 共享IPC无任务直接回调处理函数，安全OS与ccore共享物理通道 */
	ICC_CHN_SEC_VSIM = 18,        /* 私有IPC无任务直接回调处理函数，天际通安全OS与ccore物理通道 */
	ICC_CHN_SEC_RFILE = 19,       /* RFILE安全OS与ccore物理通道 */

	ICC_CHN_ID_MAX
};

/* 说明: 接收回调函数ID,子通道必须放置在, "通道名称_xxx=0和通道名称_RECV_FUNC_ID_MAX之间 */
enum ICC_S_RECV_FUNC_ID {
	IFC_RECV_FUNC_MODULE_VERIFY = 0,
	IFC_RECV_FUNC_TRNG_SEED_GET = 1,

	/* 若要在物理通道上定义子通道,请在该注释行之前定义 */
	IFC_RECV_FUNC_ID_MAX,

	VSIM_RECV_FUNC_SUB0 = 0,

	/* 若要在物理通道上定义子通道,请在该注释行之前定义 */
	VSIM_RECV_FUNC_ID_MAX,

	RFILE_RECV_FUNC_SUB0 = 0,

	/* 若要在物理通道上定义子通道,请在该注释行之前定义 */
	RFILE_RECV_FUNC_ID_MAX

};
/* 枚举定义end */

struct icc_channel_packet {
	unsigned int channel_id;               /* 该数据包记录的通道id */
	unsigned int len;                      /* 该数据包长度 */
	unsigned int src_cpu_id;               /* 该数据包的发送者的cpu id */
	unsigned int seq_num;                  /* 该数据包的序列号: 同步发送的等待队列需要用到 */
	unsigned int need_responsed: 1;        /* 该数据包是否需要回复给对方核标识bit位 */
	unsigned int is_responsed: 1;          /* 该数据包是否是对方核回复过来的标识bit位 */
	unsigned int reserved: 30;             /* 保留bit位 */
	int          data;                     /* 数据包头的context */
	unsigned int timestamp;                /* 该数据包的时间戳 */
	unsigned int task_id;                  /* 该数据包的发送者的任务id */
};

struct icc_channel_fifo {
	unsigned int  magic;     /* fifo魔数，标识通道fifo的状态 */
	unsigned int  size;      /* fifo大小 */
	unsigned int  write;     /* fifo读指针 */
	unsigned int  read;      /* fifo写指针 */
	unsigned char data[4];  /* fifo的context */
};

#define ICC_CHANNEL_PAYLOAD                        (sizeof(struct icc_channel_packet) + 4)
#define ICC_CHANNEL_ID_MAKEUP(channel_id, func_id) ((channel_id << 16) | (func_id))


typedef int (*read_cb_func)(unsigned int channel_id , unsigned int len, void *context);
typedef int (*write_cb_func)(unsigned int channel_id , void *context);

/* 对外接口声明start */
/*****************************************************************************
* 函 数 名  : bsp_icc_event_register
* 功能描述  : 使用icc通道注册回调函数接口
* 输入参数  : unsigned int channel_id  channel_id = 通道id << 16 || function_id, 使用约束:
                1) channel_id高16bit为通道标识ID，使用enum ICC_CHN_ID
                2) 低16bit为回调函数标识ID，使用ICC_RECV_FUNC_ID对应通道id的枚举值
*             read_cb_func read_cb      读回调
*             void *read_context        传给接收任务的上下文信息，做扩展用
*             write_cb_func write_cb    读回调
*             void *write_context       传给接收任务的上下文信息，做扩展用
* 输出参数  : 无
* 返 回 值  : 正确:  0;  错误: 错误码
* 说    明  : 回调函数中不能有任何会引起任务阻塞、睡眠的函数调用，如：
*             1) taskDelay()
*             2) 信号量获取
*             3) printf()
*             4) malloc()
*****************************************************************************/
int bsp_icc_event_register(unsigned int channel_id, read_cb_func read_cb, void *read_context,
			   write_cb_func write_cb, void *write_context);

/*****************************************************************************
* 函 数 名  : bsp_icc_event_unregister
* 功能描述  : 使用icc通道去注册回调函数接口
* 输入参数  : u32 channel_id  channel_id = 通道id << 16 || function_id, 使用约束:
                1) channel_id高16bit为通道标识ID，使用enum ICC_CHN_ID
                2) 低16bit为回调函数标识ID，使用ICC_RECV_FUNC_ID对应通道id的枚举值
* 输出参数  : 无
* 返 回 值  : 正确:  0;  错误: 负值
*****************************************************************************/
int bsp_icc_event_unregister(unsigned int channel_id);

/*****************************************************************************
* 函 数 名  : bsp_icc_send
* 功能描述  : icc异步发送数据接口
* 输入参数  : unsigned int cpuid       数据要发送的cpu的编号，使用约束: 要使用enum CPU_ID定义成员的枚举值
*             unsigned int channel_id  channel_id = 通道id << 16 || function_id, 使用约束:
                               1) channel_id高16bit为通道标识ID，使用enum ICC_CHN_ID的枚举值
                               2) 低16bit为回调函数标识ID，使用ICC_RECV_FUNC_ID对应通道id的枚举值
*             u8 *buffer      要发送的数据buffer的指针
*             unsigned int data_len    要发送的数据的大小, 使用约束: 最大值 < fifo_size - ICC_CHANNEL_PACKET_LEN
* 输出参数  : 无
* 返 回 值  : 正确:  实际写入fifo的大小;  错误: 负值
* 说    明  : 1) 公共通道：配套使用的注册在对方核的回调函数里必须要使用bsp_icc_read()函数把数据读走
*            2) 专用通道：支持在改通道使用模块的任务上下文中使用bsp_icc_read()函数把数据读走，但发送端必须有反压（通道数据发送缓慢）处理机制。

*****************************************************************************/
int bsp_icc_send(unsigned int cpuid, unsigned int channel_id, unsigned char *buffer, unsigned int data_len);

/*****************************************************************************
* 函 数 名  : bsp_icc_read
* 功能描述  : icc从fifo读取数据接口
* 输入参数  : unsigned int channel_id  channel_id = 通道id << 16 || function_id, 使用约束:
                1) channel_id高16bit为通道标识ID，使用enum ICC_CHN_ID
                2) 低16bit为回调函数标识ID，使用ICC_RECV_FUNC_ID对应通道id的枚举值
*             u8 *buf        要读取fifo的数据buffer的指针
*             unsigned int buf_len    数据buffer的大小
* 输出参数  : 无
* 返 回 值  : 正确:  实际从通道读取数据大小;  错误: 负值
* 说    明  : 1) 可在回调函数中使用，或使用者自己任务上下文中使用，但发送端必须有反压（通道数据发送缓慢）处理机制，以保持核间通信数据流畅通
*****************************************************************************/
int bsp_icc_read(unsigned int channel_id, unsigned char *buf, unsigned int buf_len);

#define STRU_SIZE                (sizeof(struct icc_channel_fifo))

/*安全ICC通道一共预留128K,可扩展*/
#define ICC_SEC_IFC_SIZE      (4 * 1024)
#define ICC_SEC_VSIM_SIZE     (16 * 1024)
#define ICC_SEC_RFILE_SIZE    (16 * 1024)

#endif

#ifdef __cplusplus /* __cplusplus */
}
#endif /* __cplusplus */

#endif    /*  __BSP_ICC_H__ */
