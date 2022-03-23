/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_PAL_LOG_H_
#define _CC_PAL_LOG_H_

#include "cc_pal_types.h"
#include "cc_pal_log_plat.h"

/*!
@file
@brief This file contains the PAL layer log definitions, by default the log is disabled.
*/

/* PAL log levels (to be used in CC_PAL_logLevel) */
#define CC_PAL_LOG_LEVEL_NULL      -1 /*!< \internal Disable logging */
#define CC_PAL_LOG_LEVEL_ERR       0
#define CC_PAL_LOG_LEVEL_WARN      1
#define CC_PAL_LOG_LEVEL_INFO      2
#define CC_PAL_LOG_LEVEL_DEBUG     3
#define CC_PAL_LOG_LEVEL_TRACE     4
#define CC_PAL_LOG_LEVEL_DATA      5

#ifndef CC_PAL_LOG_CUR_COMPONENT
/* Setting default component mask in case caller did not define */
/* (a mask that is always on for every log mask value but full masking) */
#define CC_PAL_LOG_CUR_COMPONENT 0xFFFFFFFF
#endif
#ifndef CC_PAL_LOG_CUR_COMPONENT_NAME
#define CC_PAL_LOG_CUR_COMPONENT_NAME "CC"
#endif

/* Select compile time log level (default if not explicitly specified by caller) */
#ifndef CC_PAL_MAX_LOG_LEVEL /* Can be overriden by external definition of this constant */
#ifdef DEBUG
#define CC_PAL_MAX_LOG_LEVEL  CC_PAL_LOG_LEVEL_ERR /*CC_PAL_LOG_LEVEL_DEBUG*/
#else /* Disable logging */
#define CC_PAL_MAX_LOG_LEVEL CC_PAL_LOG_LEVEL_NULL
#endif
#endif /*CC_PAL_MAX_LOG_LEVEL*/
/* Evaluate CC_PAL_MAX_LOG_LEVEL in case provided by caller */
#define __CC_PAL_LOG_LEVEL_EVAL(level) level
#define _CC_PAL_MAX_LOG_LEVEL __CC_PAL_LOG_LEVEL_EVAL(CC_PAL_MAX_LOG_LEVEL)


#ifdef ARM_DSM
#define CC_PalLogInit() do {} while (0)
#define CC_PalLogLevelSet(setLevel) do {} while (0)
#define CC_PalLogMaskSet(setMask) do {} while (0)
#else
#if _CC_PAL_MAX_LOG_LEVEL > CC_PAL_LOG_LEVEL_NULL
void CC_PalLogInit(void);
void CC_PalLogLevelSet(int setLevel);
void CC_PalLogMaskSet(uint32_t setMask);
extern int CC_PAL_logLevel;
extern uint32_t CC_PAL_logMask;
#else /* No log */
static inline void CC_PalLogInit(void) {}
static inline void CC_PalLogLevelSet(int setLevel) {CC_UNUSED_PARAM(setLevel);}
static inline void CC_PalLogMaskSet(uint32_t setMask) {CC_UNUSED_PARAM(setMask);}
#endif
#endif

/*! Filter logging based on logMask and dispatch to platform specific logging mechanism. */
#define _CC_PAL_LOG(level, format, ...)  \
	if (CC_PAL_logMask & CC_PAL_LOG_CUR_COMPONENT) \
		__CC_PAL_LOG_PLAT(CC_PAL_LOG_LEVEL_ ## level, "%s:%s: " format, CC_PAL_LOG_CUR_COMPONENT_NAME, __func__, ##__VA_ARGS__)

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_ERR)
#define CC_PAL_LOG_ERR(format, ... ) \
	_CC_PAL_LOG(ERR, format, ##__VA_ARGS__)
#else
#define CC_PAL_LOG_ERR( ... ) do {} while (0)
#endif

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_WARN)
#define CC_PAL_LOG_WARN(format, ... ) \
	if (CC_PAL_logLevel >= CC_PAL_LOG_LEVEL_WARN) \
		_CC_PAL_LOG(WARN, format, ##__VA_ARGS__)
#else
#define CC_PAL_LOG_WARN( ... ) do {} while (0)
#endif

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_INFO)
#define CC_PAL_LOG_INFO(format, ... ) \
	if (CC_PAL_logLevel >= CC_PAL_LOG_LEVEL_INFO) \
		_CC_PAL_LOG(INFO, format, ##__VA_ARGS__)
#else
#define CC_PAL_LOG_INFO( ... ) do {} while (0)
#endif

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_DEBUG)
#define CC_PAL_LOG_DEBUG(format, ... ) \
	if (CC_PAL_logLevel >= CC_PAL_LOG_LEVEL_DEBUG) \
		_CC_PAL_LOG(DEBUG, format, ##__VA_ARGS__)

#define CC_PAL_LOG_DUMP_BUF(msg, buf, size)		\
	do {						\
	int i;						\
	uint8_t	*pData = (uint8_t*)buf;			\
							\
	PRINTF("%s (%d):\n", msg, size);		\
	for (i = 0; i < size; i++) {			\
		PRINTF("0x%02X ", pData[i]);		\
		if ((i & 0xF) == 0xF) {			\
			PRINTF("\n");			\
		}					\
	}						\
	PRINTF("\n");					\
	} while (0)
#else
#define CC_PAL_LOG_DEBUG( ... ) do {} while (0)
#define CC_PAL_LOG_DUMP_BUF(msg, buf, size)	do {} while (0)
#endif

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_TRACE)
#define CC_PAL_LOG_TRACE(format, ... ) \
	if (CC_PAL_logLevel >= CC_PAL_LOG_LEVEL_TRACE) \
		_CC_PAL_LOG(TRACE, format, ##__VA_ARGS__)
#else
#define CC_PAL_LOG_TRACE(...) do {} while (0)
#endif

#if (_CC_PAL_MAX_LOG_LEVEL >= CC_PAL_LOG_LEVEL_TRACE)
#define CC_PAL_LOG_DATA(format, ...) \
	if (CC_PAL_logLevel >= CC_PAL_LOG_LEVEL_TRACE) \
		_CC_PAL_LOG(DATA, format, ##__VA_ARGS__)
#else
#define CC_PAL_LOG_DATA( ...) do {} while (0)
#endif

#endif /*_CC_PAL_LOG_H_*/
