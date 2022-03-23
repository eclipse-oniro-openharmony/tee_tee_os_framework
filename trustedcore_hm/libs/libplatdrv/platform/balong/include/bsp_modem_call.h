/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */
#ifndef __BSP_MODEM_CALL_H__
#define __BSP_MODEM_CALL_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * 调用安全函数支持的命令ID
 */
typedef enum FUNC_MODEM_CMD_ID {
    /*------0x600-0x800:TA-->驱动-------*/
    FUNC_TA_TO_DRV_MIN = 0x600,
    FUNC_ICC_CA_CFG_GET = 0x600, /* 获取CA session初始化配置参数 */
    FUNC_MDRV_ICC_OPEN,          /* 打开一个安全ICC通道 */
    FUNC_MDRV_ICC_CLOSE,         /* 关闭一个安全ICC通道 */
    FUNC_MDRV_ICC_WRITE,         /* 通过安全ICC通道发送数据 */
    FUNC_MDRV_ICC_READ,          /* 通过安全ICC通道读取数据 */
    FUNC_MDRV_ICC_TRYREAD,       /* 通过安全ICC通道尝试读取数据 */
    FUNC_MDRV_EFUSE_TA_READ,     /* TA读取efuse的通道*/

    /* TA-->驱动的调用请在此之前添加 */
    FUNC_TA_TO_DRV_MAX,

    /*------0x800--:CA-->驱动-----------*/
    FUNC_CA_TO_DRV_MIN = 0x800,
    FUNC_ICC_CHANNEL_RESET = 0x800,  /* ICC通道复位 */
    FUNC_ICC_MSG_SWITCH_ON,          /* 允许ICC往modem发送消息 */
    FUNC_ICC_MSG_SWITCH_OFF,         /* 禁止ICC往modem发送消息 */
    FUNC_SEC_DUMP_CHANNEL_ENABLE,    /* 异常场景通道使能传输 */
    FUNC_TRNG_SEED_REQUEST,          /* security trng seed */
    FUNC_DTS_LOAD_DTBO,              /* DTS加载校验DTBO */
    FUNC_MDRV_EFUSE_READ,            /* Efuse Read控制命令 */
    FUNC_MDRV_EFUSE_WRITE,           /* Efuse Write控制命令 */
    FUNC_MDRV_EFUSE_WRITE_WITH_DMPU, /* Efuse Write with dmpu 控制命令 */
    FUNC_MDRV_EFUSE_SEC_READ,        /* Efuse Sec Read控制命令 */
    FUNC_MDRV_EFUSE_SEC_WRITE,       /* Efuse Sec Write控制命令 */
    FUNC_MDRV_EICC_CAOPTS,           /* EICC 操作控制命令 */
    FUNC_MDRV_VERSION_INIT,          /* version 初始化 */

    /* CA-->驱动的调用请在此之前添加 */
    FUNC_CA_TO_DRV_MAX,
} FUNC_CMD_ID;

int bsp_modem_call(unsigned int func_cmd, unsigned int arg1, void *arg2, unsigned int arg3);

typedef int (*MODEM_CALL_HOOK_FUNC)(unsigned int arg1, void *arg2, unsigned int arg3);
int bsp_modem_call_register(FUNC_CMD_ID call_id, MODEM_CALL_HOOK_FUNC modem_call);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
