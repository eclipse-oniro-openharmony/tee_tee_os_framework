/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_MUTEX_PLAT_H
#define _SSI_PAL_MUTEX_PLAT_H

#ifdef __cplusplus
extern "C" {
#endif
/*
 * @brief File Description:
 *        This file contains functions for resource management (semaphor operations).
 *        The functions implementations are generally just wrappers to different operating system calls.
 *        None of the described functions will check the input parameters so the behavior
 *        of the APIs in illegal parameters case is dependent on the operating system behavior.
 *
 */

typedef uint32_t SaSi_PalMutex;

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

#ifdef __cplusplus
}
#endif

#endif
