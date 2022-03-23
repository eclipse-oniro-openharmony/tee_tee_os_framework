/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SASI_PAL_LOG_PLAT_H_
#define _SASI_PAL_LOG_PLAT_H_

#include "dx_log_mask.h"
#include <syslog.h>

/* ************* PRINTF rules **************** */
#if defined(DEBUG)

#define __SASI_PAL_LOG_PLAT(level, format, ...) syslog(level + LOG_ERR, format, ##__VA_ARGS__)

#else /* Disable all prints */

#define __SASI_PAL_LOG_PLAT(...) \
    do {                         \
    } while (0)

#endif

#endif /* _SASI_PAL_LOG_PLAT_H_ */
