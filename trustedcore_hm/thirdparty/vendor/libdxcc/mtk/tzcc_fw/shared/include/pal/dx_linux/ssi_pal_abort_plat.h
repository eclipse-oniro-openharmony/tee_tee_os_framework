/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_ABORT_PLAT_H
#define _SSI_PAL_ABORT_PLAT_H

#include "ssi_pal_log.h"
#include "ssi_pal_compiler.h"
#include "stdlib.h"

#define _SaSi_PalAbort(exp)                                               \
    do {                                                                  \
        SASI_PAL_LOG_ERR("ASSERT:%s:%d: %s", __FILE__, __LINE__, (#exp)); \
        abort();                                                          \
    } while (0)

#endif
