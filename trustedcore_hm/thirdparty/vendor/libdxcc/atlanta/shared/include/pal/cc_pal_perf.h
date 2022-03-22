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

#ifndef _CC_PAL_PERF_H_
#define _CC_PAL_PERF_H_

#ifdef LIB_PERF
#include "cc_pal_perf_plat.h"
#endif

typedef enum {
	PERF_TEST_TYPE_CC_AES_INTGR = 0x1,
	PERF_TEST_TYPE_CC_AES_INIT = 	0x2,
	PERF_TEST_TYPE_CC_AES_BLOCK = 0x3,
	PERF_TEST_TYPE_CC_AES_FIN = 	0x4,
	PERF_TEST_TYPE_HW_CMPLT = 	0x5,
	PERF_TEST_TYPE_PAL_MAP = 	0x6,
	PERF_TEST_TYPE_PAL_UNMAP = 	0x7,
	PERF_TEST_TYPE_MLLI_BUILD = 	0x8,
	PERF_TEST_TYPE_SYM_DRV_INIT = 	0x9,
	PERF_TEST_TYPE_SYM_DRV_PROC = 	0xA,
	PERF_TEST_TYPE_SYM_DRV_FIN =	0xB,
	PERF_TEST_TYPE_CC_HASH_INIT = 0xC,
	PERF_TEST_TYPE_CC_HASH_UPDATE=0xD,
	PERF_TEST_TYPE_CC_HASH_FIN = 	0xE,
	PERF_TEST_TYPE_CC_HMAC_INIT = 0xF,
	PERF_TEST_TYPE_CC_HMAC_UPDATE=0x10,
	PERF_TEST_TYPE_CC_HMAC_FIN = 	0x11,
	PERF_TEST_TYPE_CMPLT_SLEEP   = 0x12,
	PERF_TEST_TYPE_PKA_ModExp 	= 0x30,
	PERF_TEST_TYPE_TEST_BASE =	0x100,
	PERF_TEST_TYPE_MAX,
	PERF_TEST_TYPE_RESERVE32 = 	0x7FFFFFFF
}CCPalPerfType_t;


#ifdef LIB_PERF
#define CC_PAL_PERF_INIT  CC_PalPerfInit
#define CC_PAL_PERF_OPEN_NEW_ENTRY(num, type) \
		num = CC_PalPerfOpenNewEntry(type)

#define CC_PAL_PERF_CLOSE_ENTRY(num, type) \
		CC_PalPerfCloseEntry(num, type)
#define CC_PAL_PERF_DUMP   CC_PalPerfDump
#define CC_PAL_PERF_FIN    CC_PalPerfFin

/**
 * @brief   initialize performance test mechanism
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfInit(void);


/**
 * @brief   opens new entry in perf buffer to record new entry
 *
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return A non-zero value in case of failure.
 */
CCPalPerfData_t CC_PalPerfOpenNewEntry(CCPalPerfType_t entryType);


/**
 * @brief   closes entry in perf buffer previously opened by CC_PalPerfOpenNewEntry
 *
 * @param[in] idx -  index of the entry to be closed, the return value of CC_PalPerfOpenNewEntry
 * @param[in] entryType -  entry type (defined in cc_pal_perf.h) to be recorded in buffer
 *
 * @return A non-zero value in case of failure.
 */
void CC_PalPerfCloseEntry(CCPalPerfData_t idx, CCPalPerfType_t entryType);


/**
 * @brief   dumps the performance buffer
 *
 * @param[in] None
 *
 * @return None
 */
void CC_PalPerfDump(void);


/**
 * @brief   terminates resources used for performance tests
 *
 * @param[in]
 * *
 * @return None
 */
void CC_PalPerfFin(void);

#else  //LIB_PERF
#define CC_PAL_PERF_INIT()
#define CC_PAL_PERF_OPEN_NEW_ENTRY(num, type)  (num=num)
#define CC_PAL_PERF_CLOSE_ENTRY(num, type)
#define CC_PAL_PERF_DUMP()
#define CC_PAL_PERF_FIN()


typedef uint32_t CCPalPerfData_t;

#endif  //LIB_PERF


#endif /*_CC_PAL_PERF_H__*/
