/**
 * @file   : pal_log.h
 * @brief  : platform-independ log
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __PAL_LOG_H__
#define __PAL_LOG_H__
#include <pal_types.h>
#include <pal_errno.h>
#include <pal_log_plat.h>
#include <pal_exception.h>

/* #define FEATURE_ALLOC_TRACE_ENABLE 1 //trace heap alloc */
/* #define FEATURE_PAL_TRACE_ENABLE 1 //trace register */

#define PAL_LOG_NONE  (0)  /* no log info */
#define PAL_LOG_ERR    (1)
#define PAL_LOG_WARN   (2)
#define PAL_LOG_INFO   (3)
#define PAL_LOG_DEBUG  (4)

/* default log level */
#if !defined(PAL_LOG_DEFAULT)
#define PAL_LOG_DEFAULT   PAL_LOG_INFO
#endif /* PAL_LOG_DEFAULT */

/* module id allowed to debug */
#ifndef PAL_MODULE_VALID
#ifdef FEATURE_DFT_ENABLE
#define PAL_MODULE_VALID(mod) (1)
#else
#define PAL_MODULE_VALID(mod) (0)
#endif /* FEATURE_DFT_ENABLE */
#endif /* PAL_MODULE_VALID */

/**
 * @brief      : dump register or memory data
 * @param[in]  : addr   mem/reg address
 * @param[in]  : length data length
 * @param[in]  : is_reg PAL_TRUE--register format，PAL_TRUE--memory format
 * @return     : void
 */
void pal_dump(u8 *addr, u32 length, u32 is_reg);

#ifndef FEATURE_DFT_ENABLE
#define pal_get_trace() PAL_TRUE
#else
/**
 * @brief      : trace enable or not
 * @return     : ::u32
 */
u32 pal_get_trace();

/**
 * @brief      : set trace control
 * @param[in]  : enable PAL_TRUE - disable or OTHER - enable
 * @return     : void
 */
void pal_set_trace(u32 enable);
#endif /* FEATURE_DFT_ENABLE */

/* debug control */
#define PAL_LOG_ALLOWED(mod, level) \
	((PAL_LOG_NONE != PAL_LOG_DEFAULT) /* log is not none */ \
	&&  PAL_MODULE_VALID(mod)          /* module valid */ \
	&& ((level) <= PAL_LOG_DEFAULT)   /* level be allowed */ \
	)

/**< log output */
#define __PAL_OUTPUT(mod, level, fmt, ...) do { \
	if (PAL_LOG_ALLOWED(mod, level)) { \
		PAL_PRINTF(level, "[%s:%d]: "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	} \
} while (0)

#define PAL_DUMP(desc, p, size, is_reg) do {\
	PAL_PRINTF(PAL_LOG_ERR, "[%s:%d]: "desc" > addr = "PAL_FMT_PTR", len = %d", \
		__FUNCTION__, __LINE__, (u32)(intptr_t)(p), size);\
	pal_dump((u8 *)(uintptr_t)(p), (u32)(size), is_reg); \
	PAL_PRINTF(PAL_LOG_ERR, "[%s:%d]: -------------end--------\n\n", \
		__FUNCTION__, __LINE__);\
} while (0)

/**< raw data output for byte format, eg 00 11 22 33  44 55 66 77 */
#define __PAL_RAWDATA(level, desc, mem, memlen) do { \
	if (PAL_LOG_ALLOWED(BSP_THIS_MODULE, level)) { \
		PAL_DUMP(desc, mem, memlen, PAL_FALSE); \
	} \
} while (0)
/**< RAW原始数据(字节)格式输出 */
#define PAL_RAWDATA(desc, mem, memlen) __PAL_RAWDATA(PAL_LOG_INFO, desc, mem, memlen)

/**< REG格式数据输出 */
#define __PAL_REGDUMP(level, desc, mem, memlen) do { \
	if (PAL_LOG_ALLOWED(BSP_THIS_MODULE, level)) { \
		PAL_DUMP(desc, mem, memlen, PAL_TRUE); \
	} \
} while (0)
/**< REG格式数据输出 */
#define PAL_REGDUMP(desc, mem, memlen) __PAL_REGDUMP(PAL_LOG_INFO, desc, mem, memlen)

/**< error information */
#define __PAL_ERROR(mod, fmt, ...) __PAL_OUTPUT(mod, PAL_LOG_ERR, fmt, ##__VA_ARGS__)
#define PAL_ERROR(fmt, ...)        __PAL_ERROR(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/**< warn information */
#define __PAL_WARN(mod, fmt, ...)  __PAL_OUTPUT(mod, PAL_LOG_WARN, fmt, ##__VA_ARGS__)
#define PAL_WARN(fmt, ...)         __PAL_WARN(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/**< normal information */
#define __PAL_INFO(mod, fmt, ...)  __PAL_OUTPUT(mod, PAL_LOG_INFO, fmt, ##__VA_ARGS__)
#define PAL_INFO(fmt, ...)         __PAL_INFO(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/**< debug information */
#define __PAL_DEBUG(mod, fmt, ...) __PAL_OUTPUT(mod, PAL_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define PAL_DEBUG(fmt, ...)        __PAL_DEBUG(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/**
 * @brief return when express is established
 */
#define PAL_CHECK_RETURN(express, errno) do { \
	if (express) { \
        PAL_ERROR("errno = "PAL_FMT_PTR"\n", INTEGER(errno)); \
		return errno; \
	} \
} while (0)

/**
 * @brief goto when express is established
 */
#define PAL_CHECK_GOTO(express, result, handler) do { \
	if (express) { \
		ret = result;\
		PAL_ERROR(#express" err\n"); \
		goto handler; \
	} \
} while (0)

/**
 * @brief throw exception when errno isn not BSP_RET_OK
 */
#define PAL_ERR_THROW(result) do { \
	if (BSP_RET_OK != result) { \
		PAL_ERROR("Exception for errno = "PAL_FMT_PTR"\n", result); \
		pal_exception_process(BSP_THIS_MODULE, result); \
	} \
} while (0)

/**< return when result is not BSP_RET_OK */
#define PAL_ERR_RETURN(result) do { \
	ret = result; \
	if (BSP_RET_OK != ret) { \
		PAL_ERROR("errno = "PAL_FMT_PTR"\n", ret); \
		return ret; \
	} \
} while (0)

/**< goto err_hander when result is not BSP_RET_OK */
#define PAL_ERR_GOTO(result, err_hander) do { \
	ret = result; \
	if (BSP_RET_OK != ret) { \
		PAL_ERROR("errno = "PAL_FMT_PTR"\n", ret); \
		goto err_hander; \
	} \
} while (0)

#endif /* __PAL_LOG_H__ */
