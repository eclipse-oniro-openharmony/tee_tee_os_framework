/****************************************************************************//**
 * @file   : errno.h
 * @brief  : error coding
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/25
 * @author : m00172947
 * @note   :
********************************************************************************/
#ifndef __ERRNO_H__
#define __ERRNO_H__
#include <types.h>
#include <sre_debug.h> // uart_printf

typedef enum {
    RET_ERR_PARAM_NULL = -0xF000,
    RET_ERR_PARAM_INVALID,
    RET_ERR_OVERFLOW,
    RET_ERR_INSUFFICIENT,
    RET_ERR_LIMITED,
    RET_ERR_NOT_FOUND,
    RET_ERR_NOT_OPEN,
    RET_ERR_DUPLICATE,
    RET_ERR_CONNECT_FAIL,
    RET_ERR_TIME_OUT,
    RET_ERR_UNKNOWN,
    RET_ERR = -1,
    RET_OK = 0
} SYS_STATE_RET;

#define OK     (RET_OK)
#define ERROR  (RET_ERR)

#define TRUE    (1)
#define FALSE   (0)

#define INIT_OK                     (0x005AC378)
#define INIT_ERR                    (0xFFA53C00)

#ifdef FEATURE_AUTOTEST
#define SE_RET_OK   (0x5A5A0000)
#define SE_RET_ERR  (0xA5A50000)
#define EUNKNOWN    (0xA5A50001)
#endif

/**
 * @brief mudule id
*/
typedef enum {
    BSP_MODULE_SYS          = 0x00,
    BSP_MODULE_RNG          = 0x01,
    BSP_MODULE_KM           = 0x02,
    BSP_MODULE_SCE          = 0x03,
    BSP_MODULE_HASH         = 0x04,
    BSP_MODULE_MAC          = 0x05,
    BSP_MODULE_SYMM         = 0x06,
    BSP_MODULE_ECC          = 0x07,
    BSP_MODULE_RSA          = 0x08,
    BSP_MODULE_PKE          = 0x09,
    BSP_MODULE_SCRAMBLING   = 0x0A,
    BSP_MODULE_HYBRID       = 0x0B,
    BSP_MODULE_SEC          = 0x20,     /**< Reserve 32 for security engine */
    BSP_MODULE_NVM          = 0x21,
    BSP_MODULE_POWER        = 0x22,     /* EPS power */
    BSP_MODULE_LIBC         = 0x23,     /* libc module */
    BSP_MODULE_TIMER        = 0x24,     /* timer module */
    BSP_MODULE_UART         = 0x25,     /* uart module */
    BSP_MODULE_WDG          = 0x26,     /* watch dog module */
    BSP_MODULE_IPC          = 0x27,     /* ipc module */
    BSP_MODULE_UNKNOWN      = 0x7F,     /**< unknown module (support maximum 127) */
} bsp_module_e;

/**
 * @brief error code
 *       Note: increase in order, not allowed to modify existed errcode
 *             0x5A is not allowed to use since it is same as OK
*/
typedef enum {
    ERRCODE_NULL                = 0x01,     /**< pointer is null */
    ERRCODE_PARAMS              = 0x02,     /**< parameter error */
    ERRCODE_INVALID             = 0x03,     /**< data is invalid */
    ERRCODE_NOFOUND             = 0x04,     /**< not found */
    ERRCODE_MEMORY              = 0x05,     /**< out of memory or error */
    ERRCODE_VERIFY              = 0x06,     /**< verify failed */
    ERRCODE_TIMEOUT             = 0x07,     /**< timeout error */
    ERRCODE_READ                = 0x08,     /**< read failed */
    ERRCODE_WRITE               = 0x09,     /**< write failed */
    ERRCODE_REQUEST             = 0x0A,     /**< request failed for communication */
    ERRCODE_ALARM               = 0x0B,     /**< abnormal alarm */
    ERRCODE_UNSUPPORT           = 0x0C,     /**< not supported */
    ERRCODE_ATTACK              = 0x0D,     /**< be attacked */
    ERRCODE_SYS                 = 0x0E,     /**< system error for irq, cpu, libc and so on */
    ERRCODE_BUSY                = 0x0F,     /**< busy status */
    ERRCODE_UNKNOWN             = 0xFF,     /**< unknown(default, max enum value) */
} errcode_e;

#define BSP_RET_OK               (0x00005A5A)    /**< success */
#define ERR_BSP_PREFIX          (0xA5)           /**< prefix for error coding */

#define BSP_IS_SYMM(module)     ((BSP_MODULE_KM <= (module)) && ((module) <= BSP_MODULE_SYMM))
#define BSP_IS_PKE(module)      ((BSP_MODULE_ECC <= (module)) && ((module) <= BSP_MODULE_PKE))

#define BSP_ERR_GOTO(_ret, err_handler)       do { \
    ret = _ret; \
    if (BSP_RET_OK != ret) { \
        uart_printf("errno = %x\n", ret); \
        goto err_handler; \
    } \
} while (0)

#define CHECK_INPUT_ARGUMENT(express) do { \
    if (express == NULL) { \
        PRINT_ERR("argument NULL error! \n"); \
        return ERROR; \
    } \
} while (0);

/****************************************************************************//**
 * @brief      : error coding
 * @param[in]  : prefix     error prefix is a bigger value and set to 0x5A for safety
 * @param[in]  : line       code line, 1 byte, mod 256, range is 0~0xFF
 * @param[in]  : module     module id, 1 byte(0~127) refer to ::bsp_module_e
 *                          the highest bit 1 is HAL, 0 is DRV
 * @param[in]  : errcode    error code£¬refer to::errcode_e
 * @return     : coding value
 * @note       :
********************************************************************************/
#define ERR_MAKEUP(prefix, line, module, errcode) \
    (err_bsp_t)(((u32)(prefix) << 24) | (((line) & 0xFF) << 16) | (((module) & 0xFF) << 8) | ((errcode) & 0xFF))

/**< get module id */
#define ERR_GET_MODULE(errno)       (((errno) >> 8) & 0x7F)

/**< get error code */
#define ERR_GET_ERRCODE(errno)      ((errno) & 0xFF)

/**< error coding of drv  */
#define __ERR_DRV(module, errcode)  ERR_MAKEUP(ERR_BSP_PREFIX, __LINE__, module, errcode)
#define ERR_DRV(errcode)             __ERR_DRV(BSP_THIS_MODULE, errcode)

/**< set default error coding of drv */
#define SET_DEF_DRV_ERR(ret)   do { \
    ret = ERR_DRV(ERRCODE_UNKNOWN); \
    (void)(ret); /* UNUSED */ \
} while (0)

/**< error coding of api */
#define __ERR_HAL(module, errcode)  (__ERR_DRV(module, errcode) | 0x8000)
#define ERR_HAL(errcode)             __ERR_HAL(BSP_THIS_MODULE, errcode)

/**< set default error coding of api */
#define SET_DEF_HAL_ERR(ret)   do { \
    ret = ERR_HAL(ERRCODE_UNKNOWN); \
    (void)(ret); /* UNUSED */ \
} while (0)
#endif
