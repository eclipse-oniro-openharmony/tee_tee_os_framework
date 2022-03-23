/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_LOG_PLAT_H_
#define _SSI_PAL_LOG_PLAT_H_

#include "dx_log_mask.h"
#include <stdio.h>
#include "drStd.h"
#include "dr_api/dr_api.h"

/* ************* PRINTF rules **************** */
#if defined(DEBUG)

#define PRINTF drApiLogPrintf

#else /* Disable all prints */

#define PRINTF(...) \
    do {            \
    } while (0)

#endif

#define __SASI_PAL_LOG_PLAT(level, format, ...) PRINTF(format, ##__VA_ARGS__)

#endif /* _SSI_PAL_LOG_PLAT_H_ */
