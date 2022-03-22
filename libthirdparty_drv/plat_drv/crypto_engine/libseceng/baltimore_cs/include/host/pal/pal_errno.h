/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: define error coding
 * Author     : m00475438
 * Create     : 2018/08/10
 */
#ifndef __PAL_ERRNO_H__
#define __PAL_ERRNO_H__
#include <pal_errno_plat.h>

/* err_bsp_t   ; errno type for seceng errno */
/* bsp_module_e: enum type for seceng module id:
 *	 BSP_MODULE_RNG,
 *	 BSP_MODULE_KM,
 *	 BSP_MODULE_SCE,
 *	 BSP_MODULE_HASH,
 *	 BSP_MODULE_MAC,
 *	 BSP_MODULE_SYMM,
 *	 BSP_MODULE_ECC,
 *	 BSP_MODULE_RSA,
 *	 BSP_MODULE_PKE,
 */

/* errcode_e  : enum type for seceng error code:
 *	 ERRCODE_NULL,      // pointer is null
 *	 ERRCODE_PARAMS,    // parameter error
 *	 ERRCODE_INVALID,   // data is invalid
 *	 ERRCODE_NOFOUND,   // not found
 *	 ERRCODE_MEMORY,    // out of memory or error
 *	 ERRCODE_VERIFY,    // verify failed
 *	 ERRCODE_TIMEOUT,   // timeout error
 *	 ERRCODE_READ,      // read failed
 *	 ERRCODE_WRITE,     // write failed
 *	 ERRCODE_ALARM,     // abnormal alarm
 *	 ERRCODE_UNSUPPORT, // not supported
 *	 ERRCODE_ATTACK,    // be attacked
 *	 ERRCODE_SYS,       // system error for irq, cpu, libc and so on
 *	 ERRCODE_BUSY,      // busy status
 */

/* BSP_RET_OK                : for success */
#ifndef BSP_RET_OK
#define BSP_RET_OK           0x00005A5A    /**< success */
#endif /* BSP_RET_OK */

/*
 *  error coding
 *  prefix     error prefix is a bigger value and set to 0xA for safety
 *  line       code line, 1 byte, mod 0xFFF, range is 0~0xFFF
 *  module     module id, 1 byte(0~127) refer to ::bsp_module_e
 *             the highest bit 1 is HAL, 0 is DRV
 *  errcode    error code, refer to::errcode_e coding value
 * [note]: errno must include module id and errcode
 */
#ifndef ERR_MAKEUP
#define ERR_MAKEUP(prefix, line, module, errcode) \
	(err_bsp_t)((((u32)(prefix) & 0xF0) << 24) | \
		(((line) & 0xFFF) << 16) | \
		(((module) & 0xFF) << 8) | \
		((errcode) & 0xFF))
#endif /* ERR_MAKEUP */

/**< get module id */
#ifndef ERR_GET_MODULE
#define ERR_GET_MODULE(errno)       (((u32)(errno) >> 8) & 0x3F)
#endif /* ERR_GET_MODULE */

/**< get error code */
#ifndef ERR_GET_ERRCODE
#define ERR_GET_ERRCODE(errno)      ((u32)(errno) & 0xFF)
#endif /* ERR_GET_ERRCODE */

#ifndef ERR_BSP
#define ERR_BSP(module, errcode)     ERR_MAKEUP(0xA0, __LINE__, module, errcode)
#endif /* __ERR_BSP */

/* error coding of drv  */
#ifndef ERR_DRV
#define ERR_DRV(errcode)             ERR_BSP(BSP_THIS_MODULE, errcode)
#endif /* ERR_DRV */

/* error coding of hal */
#ifndef ERR_HAL
#define ERR_HAL(errcode)             (ERR_DRV(errcode) | 0x4000)
#endif /* ERR_HAL */

/* error coding of api */
#ifndef ERR_API
#define ERR_API(errcode)             (ERR_DRV(errcode) | 0x8000)
#endif /* ERR_API */

#endif /* __PAL_ERRNO_H__ */

