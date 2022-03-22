/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

// #include <syslog.h>
#include "ssi_pal_types.h"
#include "ssi_pal_log.h"

#if 0
#ifdef DEBUG
#define SYSLOG_OPTIONS (LOG_CONS | LOG_NDELAY | LOG_PID | LOG_PERROR)
#else
#define SYSLOG_OPTIONS (LOG_CONS | LOG_NDELAY | LOG_PID)
#endif
#endif

int SaSi_PAL_logLevel     = SASI_PAL_MAX_LOG_LEVEL;
uint32_t SaSi_PAL_logMask = 0xFFFFFFFF;

void SaSi_PalLogInit(void)
{
    static int initOnce = 0;

#if 0
    if (!initOnce)
        openlog("Dx.Proc.", SYSLOG_OPTIONS, LOG_USER);
#endif
    initOnce = 1;
}

void SaSi_PalLogLevelSet(int setLevel)
{
    SaSi_PAL_logLevel = setLevel;
}

void SaSi_PalLogMaskSet(uint32_t setMask)
{
    SaSi_PAL_logMask = setMask;
}
