/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_PERF_H_
#define _SSI_PAL_PERF_H_

#ifdef LIB_PERF
#include "ssi_pal_perf_plat.h"
#endif

typedef enum {
    PERF_TEST_TYPE_SaSi_AES_INTGR   = 0x1,
    PERF_TEST_TYPE_SaSi_AES_INIT    = 0x2,
    PERF_TEST_TYPE_SaSi_AES_BLOCK   = 0x3,
    PERF_TEST_TYPE_SaSi_AES_FIN     = 0x4,
    PERF_TEST_TYPE_HW_CMPLT         = 0x5,
    PERF_TEST_TYPE_PAL_MAP          = 0x6,
    PERF_TEST_TYPE_PAL_UNMAP        = 0x7,
    PERF_TEST_TYPE_MLLI_BUILD       = 0x8,
    PERF_TEST_TYPE_SYM_DRV_INIT     = 0x9,
    PERF_TEST_TYPE_SYM_DRV_PROC     = 0xA,
    PERF_TEST_TYPE_SYM_DRV_FIN      = 0xB,
    PERF_TEST_TYPE_SaSi_HASH_INIT   = 0xC,
    PERF_TEST_TYPE_SaSi_HASH_UPDATE = 0xD,
    PERF_TEST_TYPE_SaSi_HASH_FIN    = 0xE,
    PERF_TEST_TYPE_SaSi_HMAC_INIT   = 0xF,
    PERF_TEST_TYPE_SaSi_HMAC_UPDATE = 0x10,
    PERF_TEST_TYPE_SaSi_HMAC_FIN    = 0x11,
    PERF_TEST_TYPE_CMPLT_SLEEP      = 0x12,
    PERF_TEST_TYPE_PKA_ModExp       = 0x30,
    PERF_TEST_TYPE_TEST_BASE        = 0x100,
    PERF_TEST_TYPE_MAX,
    PERF_TEST_TYPE_RESERVE32 = 0x7FFFFFFF
} SaSiPalPerfType_t;

#ifdef LIB_PERF
#define SASI_PAL_PERF_INIT                      SaSi_PalPerfInit
#define SASI_PAL_PERF_OPEN_NEW_ENTRY(num, type) num = SaSi_PalPerfOpenNewEntry(type)

#define SASI_PAL_PERF_CLOSE_ENTRY(num, type) SaSi_PalPerfCloseEntry(num, type)
#define SASI_PAL_PERF_DUMP                   SaSi_PalPerfDump
#define SASI_PAL_PERF_FIN                    SaSi_PalPerfFin

/*
 * @brief   initialize performance test mechanism
 *
 * @param[in]
 * *
 * @return None
 */
void SaSi_PalPerfInit(void);

/*
 * @brief   opens new entry in perf buffer to record new entry
 *
 * @param[in] entryType -  entry type (defined in ssi_pal_perf.h) to be recorded in buffer
 *
 * @return A non-zero value in case of failure.
 */
SaSi_PalPerfData_t SaSi_PalPerfOpenNewEntry(SaSiPalPerfType_t entryType);

/*
 * @brief   closes entry in perf buffer previously opened by SaSi_PalPerfOpenNewEntry
 *
 * @param[in] idx -  index of the entry to be closed, the return value of SaSi_PalPerfOpenNewEntry
 * @param[in] entryType -  entry type (defined in ssi_pal_perf.h) to be recorded in buffer
 *
 * @return A non-zero value in case of failure.
 */
void SaSi_PalPerfCloseEntry(SaSi_PalPerfData_t idx, SaSiPalPerfType_t entryType);

/*
 * @brief   dumps the performance buffer
 *
 * @param[in] None
 *
 * @return None
 */
void SaSi_PalPerfDump(void);

/*
 * @brief   terminates resources used for performance tests
 *
 * @param[in]
 * *
 * @return None
 */
void SaSi_PalPerfFin(void);

#else // LIB_PERF
#define SASI_PAL_PERF_INIT()
#define SASI_PAL_PERF_OPEN_NEW_ENTRY(num, type) (num = num)
#define SASI_PAL_PERF_CLOSE_ENTRY(num, type)
#define SASI_PAL_PERF_DUMP()
#define SASI_PAL_PERF_FIN()

typedef uint32_t SaSi_PalPerfData_t;

#endif // LIB_PERF

#endif /* _SSI_PAL_PERF_H__ */
