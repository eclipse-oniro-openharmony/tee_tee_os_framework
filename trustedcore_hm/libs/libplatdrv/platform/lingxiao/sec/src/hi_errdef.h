/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Description: header files
 * Author: hsan
 * Create: 2019-1-31
 * History: 2019-1-31 hsan code restyle
 */

#ifndef __HI_ERRDEF_H__
#define __HI_ERRDEF_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*
 * 海思使用：0x00000000 - 0x0FFFFFFF
 * 按照字母顺序排列
 */
enum hi_ret_base_e {
	/* 返回成功 */
	HI_RET_SUCC                     = 0,
	/* 返回通用错误码 */
	HI_RET_FAIL                     = 0xFFFFFFFF,
	/* 返回码起始数值 */
	HI_RET_BASEVALUE                = 0x70000000,
	/* 芯片不支持该功能 */
	HI_RET_CHIP_NOT_SUPPORTED       = (HI_RET_BASEVALUE | 0x01),
	/* 芯片号错误 */
	HI_RET_CHIP_ID_ERROR            = (HI_RET_BASEVALUE | 0x02),
	/* CRC校验错误错误 */
	HI_RET_CRC_ERR                  = (HI_RET_BASEVALUE | 0x03),
	/* 返回设备忙 */
	HI_RET_DEVBUSY                  = (HI_RET_BASEVALUE | 0x04),
	/* 返回设备空 */
	HI_RET_DEVEMPTY                 = (HI_RET_BASEVALUE | 0x05),
	/* 返回设备满 */
	HI_RET_DEVFULL                  = (HI_RET_BASEVALUE | 0x06),
	/* 返回设备超时 */
	HI_RET_DEVTIMEOUT               = (HI_RET_BASEVALUE | 0x07),
	/* 设备未使能 */
	HI_RET_DEVCLOSE                 = (HI_RET_BASEVALUE | 0x08),
	/* 打开文件错误 */
	HI_RET_FILE_OPEN_FAIL           = (HI_RET_BASEVALUE | 0x09),
	/* 关闭文件错误 */
	HI_RET_FILE_CLOSE_FAIL          = (HI_RET_BASEVALUE | 0x0A),
	/* 读文件错误 */
	HI_RET_FILE_READ_FAIL           = (HI_RET_BASEVALUE | 0x0B),
	/* 写文件错误 */
	HI_RET_FILE_WRITE_FAIL          = (HI_RET_BASEVALUE | 0x0C),
	/* 初始化失败 */
	HI_RET_INIT_FAIL                = (HI_RET_BASEVALUE | 0x0D),
	/* 返回item不存在 */
	HI_RET_ITEM_NOTEXIST            = (HI_RET_BASEVALUE | 0x0E),
	/* 返回item已经存在 */
	HI_RET_ITEM_EXIST               = (HI_RET_BASEVALUE | 0x0F),
	/* 返回item表项满 */
	HI_RET_ITEM_FULL                = (HI_RET_BASEVALUE | 0x10),
	/* 返回item表项异常 */
	HI_RET_ITEM_EXCEPT              = (HI_RET_BASEVALUE | 0x11),
	/* 返回无效参数 */
	HI_RET_INVALID_PARA             = (HI_RET_BASEVALUE | 0x12),
	/* 错误的状态 */
	HI_RET_INVALID_STATE            = (HI_RET_BASEVALUE | 0x13),
	/* 非法VLAN ID */
	HI_RET_INVALID_VLAN_ID          = (HI_RET_BASEVALUE | 0x14),
	/* 优先级类型错误 */
	HI_RET_INVALID_PRIORITY_TYPE    = (HI_RET_BASEVALUE | 0x15),
	/* MAC地址老化时间非法 */
	HI_RET_INVALID_MAC_AGE_TIME     = (HI_RET_BASEVALUE | 0x16),
	/* MAC地址学习数非法 */
	HI_RET_INVALID_MAC_LEARN_LIMIT  = (HI_RET_BASEVALUE | 0x17),
	/* MAC地址非法 */
	HI_RET_INVALID_MAC_ADDR         = (HI_RET_BASEVALUE | 0x18),
	/* 端口TAG类型错误 */
	HI_RET_INVALID_PORT_TAG_MODE    = (HI_RET_BASEVALUE | 0x19),
	/* 错误的地址 */
	HI_RET_INVALID_ADDR             = (HI_RET_BASEVALUE | 0x1A),
	/* 分配内存失败 */
	HI_RET_MALLOC_FAIL              = (HI_RET_BASEVALUE | 0x1B),
	/* 释放内存失败 */
	HI_RET_MFREE_FAIL               = (HI_RET_BASEVALUE | 0x1C),
	/* 未知的消息类型 */
	HI_RET_MSG_UNKNOWN              = (HI_RET_BASEVALUE | 0x1D),
	/* 接收到的消息长度错误 */
	HI_RET_MSG_RCV_ERRSIZE          = (HI_RET_BASEVALUE | 0x1E),
	/* 返回输入空指针 */
	HI_RET_NULLPTR                  = (HI_RET_BASEVALUE | 0x1F),
	/* 返回不支持 */
	HI_RET_NOTSUPPORT               = (HI_RET_BASEVALUE | 0x20),
	/* 返回超出系统范围 */
	HI_RET_OUTRANG                  = (HI_RET_BASEVALUE | 0x21),
	/* 写寄存器失败 */
	HI_RET_REG_WRITE_ERR            = (HI_RET_BASEVALUE | 0x22),
	/* 读寄存器失败 */
	HI_RET_REG_READ_ERR             = (HI_RET_BASEVALUE | 0x23),
	/* 重复操作 */
	HI_RET_REPEAT_OPER              = (HI_RET_BASEVALUE | 0x24),
	/* 系统调用失败 */
	HI_RET_SYS_CALLFAIL             = (HI_RET_BASEVALUE | 0x25),
	/* 执行失败 */
	HI_RET_SYS_EXCEPTION            = (HI_RET_BASEVALUE | 0x26),
	/* 等待信号返回 */
	HI_RET_SIGNAL                   = (HI_RET_BASEVALUE | 0x27),
	/* 发送超时 */
	HI_RET_TIMEOUT                  = (HI_RET_BASEVALUE | 0x28),
	/* 创建定时器失败 */
	HI_RET_TIMER_CREATE_FAIL        = (HI_RET_BASEVALUE | 0x29),
	/* 表满 */
	HI_RET_TABLE_FULL               = (HI_RET_BASEVALUE | 0x2A),
	/* 表中已存在 */
	HI_RET_TABLE_EXIST              = (HI_RET_BASEVALUE | 0x2B),
	/* 表中不存在 */
	HI_RET_TABLE_NOTEXIST           = (HI_RET_BASEVALUE | 0x2C),
	/* 返回item表项异常 */
	HI_RET_TABLE_EXCEPT             = (HI_RET_BASEVALUE | 0x2D),
	/* 没有初始化 */
	HI_RET_UNINIT                   = (HI_RET_BASEVALUE | 0x2E),
	/* 已经初始化 */
	HI_RET_ALREADYINIT              = (HI_RET_BASEVALUE | 0x2F),
	/* 返回没有打开或者激活 */
	HI_RET_UNACTIVE                 = (HI_RET_BASEVALUE | 0x30),
	/* 返回创建进程失败 */
	HI_RET_FORKFAIL                 = (HI_RET_BASEVALUE | 0x31),
	/* 返回没有发现 */
	HI_RET_NOTFIND                  = (HI_RET_BASEVALUE | 0x32),
	/* 返回未期待异常 */
	HI_RET_UNEXCEPT                 = (HI_RET_BASEVALUE | 0x33),
	/* 返回期待非空 */
	HI_RET_NOTEMPTY                 = (HI_RET_BASEVALUE | 0x34),
	/* 线程创建失败 */
	HI_RET_THREAD_CREATE_FAIL       = (HI_RET_BASEVALUE | 0x35),
	/* 返回操作终止 */
	HI_RET_STOP                     = (HI_RET_BASEVALUE | 0X37),
};

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* __HI_ERRDEF_H__ */
