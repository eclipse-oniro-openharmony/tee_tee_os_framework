/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: platform-independ log
 * Author     : m00475438
 * Create     : 2018/08/15
 */
#ifndef __PAL_LOG_H__
#define __PAL_LOG_H__
#include <common_define.h>
#include <pal_log_plat.h>

/* #define FEATURE_ALLOC_TRACE_ENABLE 1 //trace heap alloc */
/* #define FEATURE_PAL_TRACE_ENABLE 1 //trace register */

#define PAL_LOG_NONE  0  /* no log info */
#define PAL_LOG_ERR    1
#define PAL_LOG_WARN   2
#define PAL_LOG_INFO   3
#define PAL_LOG_DEBUG  4

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

#ifndef PAL_FMT_PTR
	#define PAL_FMT_PTR "%p"
#endif /* PAL_FMT_PTR */

#ifndef PAL_FMT_HEX
	#define PAL_FMT_HEX "0x%08X"
#endif /* PAL_FMT_HEX */

/**
 * @brief      : dump register or memory data
 * @param[in]  : addr   mem/reg address
 * @param[in]  : length data length
 * @param[in]  : is_reg PAL_TRUE--register format, PAL_TRUE--memory format
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
u32 pal_get_trace(void);

/**
 * @brief      : set trace control
 * @param[in]  : enable PAL_TRUE - disable or OTHER - enable
 * @return     : void
 */
void pal_set_trace(u32 enable);
#endif /* FEATURE_DFT_ENABLE */

/* debug control */
#define PAL_LOG_ALLOWED(mod, level) \
	((PAL_LOG_NONE != PAL_LOG_DEFAULT) && /* log is not none */ \
	 PAL_MODULE_VALID(mod) &&             /* module valid */ \
	 ((level) <= PAL_LOG_DEFAULT)         /* level be allowed */ \
	)

/* log output */
#define __PAL_OUTPUT(mod, level, fmt, ...) do { \
	if (PAL_LOG_ALLOWED(mod, level)) { \
		PAL_LOG(level, "[%s:%d]: "fmt, \
			__func__, __LINE__, ##__VA_ARGS__); \
	} \
} while (0)

#define PAL_DUMP(desc, p, size, is_reg) do {\
	if (PAL_LOG_ALLOWED(BSP_THIS_MODULE, PAL_LOG_INFO)) { \
		PAL_PRINTF("[%s:%d]: " desc " > addr = " PAL_FMT_PTR \
			   ", len = %d", __func__, __LINE__, PTR(p), size); \
		pal_dump((u8 *)PTR(p), (u32)(size), is_reg); \
		PAL_PRINTF("[%s:%d]: -------------end--------\n\n", \
			   __func__, __LINE__); \
	} \
} while (0)

/* data output by bytes */
#define PAL_RAWDATA(desc, mem, memlen) \
	PAL_DUMP(desc, mem, memlen, PAL_FALSE)

/* data(register) output by words */
#define PAL_REGDUMP(desc, mem, memlen) \
	PAL_DUMP(desc, mem, memlen, PAL_TRUE)

/* error information */
#define __PAL_ERROR(mod, fmt, ...) \
	__PAL_OUTPUT(mod, PAL_LOG_ERR, fmt, ##__VA_ARGS__)
#define PAL_ERROR(fmt, ...)        \
	__PAL_ERROR(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/* warn information */
#define __PAL_WARN(mod, fmt, ...)  \
	__PAL_OUTPUT(mod, PAL_LOG_WARN, fmt, ##__VA_ARGS__)
#define PAL_WARN(fmt, ...)         \
	__PAL_WARN(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/* normal information */
#define __PAL_INFO(mod, fmt, ...)  \
	__PAL_OUTPUT(mod, PAL_LOG_INFO, fmt, ##__VA_ARGS__)
#define PAL_INFO(fmt, ...)         \
	__PAL_INFO(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

/* debug information */
#define __PAL_DEBUG(mod, fmt, ...) \
	__PAL_OUTPUT(mod, PAL_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define PAL_DEBUG(fmt, ...)        \
	__PAL_DEBUG(BSP_THIS_MODULE, fmt, ##__VA_ARGS__)

#if !defined(FEATURE_DFT_ENABLE) || defined(FEATURE_STATIC_CHECK)
#define PAL_CHECK(express) (express)
#else
u32 pal_check(u32 log_enable, u32 matched, const char *pfunc, u32 line);

#define PAL_CHECK(express) \
	(pal_check(PAL_LOG_ALLOWED(BSP_THIS_MODULE, PAL_LOG_ERR), \
		   (express) ? PAL_TRUE : PAL_FALSE, __func__, __LINE__))
#endif /* FEATURE_DFT_ENABLE */

#endif /* __PAL_LOG_H__ */
