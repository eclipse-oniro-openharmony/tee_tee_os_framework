/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: adapt error code
 * Create     : 2019/08/25
 */
#ifndef __PAL_ERRNO_PLAT_H__
#define __PAL_ERRNO_PLAT_H__

/**
 * @brief mudule id
 */
enum mudule_id {
	BSP_MODULE_SYS        = 0x00,
	BSP_MODULE_RNG        = 0x01,
	BSP_MODULE_KM         = 0x02,
	BSP_MODULE_SCE        = 0x03,
	BSP_MODULE_HASH       = 0x04,
	BSP_MODULE_MAC        = 0x05,
	BSP_MODULE_SYMM       = 0x06,
	BSP_MODULE_ECC        = 0x07,
	BSP_MODULE_RSA        = 0x08,
	BSP_MODULE_PKE        = 0x09,
	BSP_MODULE_SCRAMBLING = 0x0A,
	BSP_MODULE_HYBRID     = 0x0B,
	BSP_MODULE_SM9        = 0x0C,
	BSP_MODULE_REE_PKE    = 0x0D,
	BSP_MODULE_ENGCTRL    = 0x0E,
	BSP_MODULE_SEC        = 0x20, /* Reserve 32 for security engine */
	BSP_MODULE_NVM        = 0x21,
	BSP_MODULE_POWER      = 0x22, /* EPS power */
	BSP_MODULE_LIBC       = 0x23, /* libc module */
	BSP_MODULE_TIMER      = 0x24, /* timer module */
	BSP_MODULE_UART       = 0x25, /* uart module */
	BSP_MODULE_WDG        = 0x26, /* watch dog module */
	BSP_MODULE_IPC        = 0x27, /* ipc module */
	BSP_MODULE_UNKNOWN    = 0x7F, /* unknown module */
};

/**
 * @brief error code
 *       Note: increase in order, not allowed to modify existed errcode
 *             0x5A is not allowed to use since it is same as OK
 */
enum errcode {
	ERRCODE_NULL      = 0x01, /* pointer is null */
	ERRCODE_PARAMS    = 0x02, /* parameter error */
	ERRCODE_INVALID   = 0x03, /* data is invalid */
	ERRCODE_NOFOUND   = 0x04, /* not found */
	ERRCODE_MEMORY    = 0x05, /* out of memory or error */
	ERRCODE_VERIFY    = 0x06, /* verify failed */
	ERRCODE_TIMEOUT   = 0x07, /* timeout error */
	ERRCODE_READ      = 0x08, /* read failed */
	ERRCODE_WRITE     = 0x09, /* write failed */
	ERRCODE_REQUEST   = 0x0A, /* request failed for communication */
	ERRCODE_ALARM     = 0x0B, /* abnormal alarm */
	ERRCODE_UNSUPPORT = 0x0C, /* not supported */
	ERRCODE_ATTACK    = 0x0D, /* be attacked */
	ERRCODE_SYS       = 0x0E, /* system error, irq, cpu, libc etc. */
	ERRCODE_BUSY      = 0x0F, /* busy status */
	ERRCODE_UNKNOWN   = 0xFF, /* unknown(default, max enum value) */
};

#endif /* __PAL_ERRNO_PLAT_H__ */

