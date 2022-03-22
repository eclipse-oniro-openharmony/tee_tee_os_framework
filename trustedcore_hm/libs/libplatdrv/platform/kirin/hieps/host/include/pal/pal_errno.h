/**
 * @file   : pal_errno.h
 * @brief  : define error coding
 *           platform-dependent errno is defined in pal_errno_plat.h
 *           platform-independent error coding is defined in pal_errno.h
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/10
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __PAL_ERRNO_H__
#define __PAL_ERRNO_H__
#include <pal_errno_plat.h>

/* err_bsp_t   ; errno type for seceng errno */
/* bsp_module_e: enum type for seceng module id:
	 BSP_MODULE_RNG,
	 BSP_MODULE_KM,
	 BSP_MODULE_SCE,
	 BSP_MODULE_HASH,
	 BSP_MODULE_MAC,
	 BSP_MODULE_SYMM,
	 BSP_MODULE_ECC,
	 BSP_MODULE_RSA,
	 BSP_MODULE_PKE,
 */

/* errcode_e  : enum type for seceng error code:
	 ERRCODE_NULL,      // pointer is null
	 ERRCODE_PARAMS,    // parameter error
	 ERRCODE_INVALID,   // data is invalid
	 ERRCODE_NOFOUND,   // not found
	 ERRCODE_MEMORY,    // out of memory or error
	 ERRCODE_VERIFY,    // verify failed
	 ERRCODE_TIMEOUT,   // timeout error
	 ERRCODE_READ,      // read failed
	 ERRCODE_WRITE,     // write failed
	 ERRCODE_ALARM,     // abnormal alarm
	 ERRCODE_UNSUPPORT, // not supported
	 ERRCODE_ATTACK,    // be attacked
	 ERRCODE_SYS,       // system error for irq, cpu, libc and so on
	 ERRCODE_BUSY,      // busy status
 */

/* BSP_RET_OK                : for success */

/* [note]: errno must include module id and errcode */
/* ERR_GET_MODULE(errno)     : get module id */
/* ERR_GET_ERRCODE(errno)    : get error code */
/* __ERR_DRV(module, errcode): error coding of drv */
/* __ERR_HAL(module, errcode): error coding of api */

/**< error coding of drv  */
#ifndef ERR_DRV
#define ERR_DRV(errcode)             __ERR_DRV(BSP_THIS_MODULE, errcode)
#endif /* ERR_DRV */

/**< set default error coding of drv */
#ifndef ERR_SET_DEF_DRV
#define ERR_SET_DEF_DRV(ret)   do { \
	ret = ERR_DRV(ERRCODE_UNKNOWN); \
	(void)(ret); /* UNUSED */ \
} while (0)
#endif /* ERR_SET_DEF_DRV */

/**< error coding of hal */
#ifndef ERR_HAL
#define ERR_HAL(errcode)             __ERR_HAL(BSP_THIS_MODULE, errcode)
#endif /* ERR_HAL */

/**< error coding of api */
#ifndef ERR_API
#define __ERR_API(module, errcode)  (__ERR_DRV(module, errcode) | 0x8000)
#define ERR_API(errcode)             __ERR_API(BSP_THIS_MODULE, errcode)
#endif /* ERR_API */

/**< set default error coding of api */
#ifndef ERR_SET_DEF_HAL
#define ERR_SET_DEF_HAL(ret)   do { \
	ret = ERR_HAL(ERRCODE_UNKNOWN); \
	(void)(ret); /* UNUSED */ \
} while (0)
#endif /* ERR_SET_DEF_HAL */

#endif /* __PAL_ERRNO_H__ */

