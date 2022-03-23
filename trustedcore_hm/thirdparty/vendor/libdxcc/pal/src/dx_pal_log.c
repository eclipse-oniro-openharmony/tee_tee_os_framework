/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

// #include <syslog.h>
#include "dx_pal_types.h"
#include "dx_pal_log.h"

#ifdef DEBUG
#define SYSLOG_OPTIONS (LOG_CONS | LOG_NDELAY | LOG_PID | LOG_PERROR)
#else
#define SYSLOG_OPTIONS (LOG_CONS | LOG_NDELAY | LOG_PID)
#endif

int DX_PAL_logLevel     = DX_PAL_MAX_LOG_LEVEL;
uint32_t DX_PAL_logMask = 0xFFFFFFFF;

void DX_PAL_LogInit(void)
{
    /*
    static int initOnce = 0;

    if (!initOnce)
        openlog("Dx.Proc.", SYSLOG_OPTIONS, LOG_USER);
    initOnce = 1;
    */
}

void DX_PAL_LogLevelSet(int setLevel)
{
    DX_PAL_logLevel = setLevel;
}

void DX_PAL_LogMaskSet(uint32_t setMask)
{
    DX_PAL_logMask = setMask;
}
