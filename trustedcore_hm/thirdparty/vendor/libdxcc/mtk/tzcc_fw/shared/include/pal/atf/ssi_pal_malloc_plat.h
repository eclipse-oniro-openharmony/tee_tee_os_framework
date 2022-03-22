/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_MEMALLOC_INT_H
#define _SSI_PAL_MEMALLOC_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
/*
 * @brief File Description:
 *        This file contains wrappers for memory operations APIs.
 */

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief A wrapper over malloc functionality. The function allocates a buffer according to given size
 *
 */
#define _SaSi_PalMemMalloc malloc

/*
 * @brief A wrapper over realloc functionality. The function allocates and copy a buffer
 *        according to size
 *
 */
#define _SaSi_PalMemRealloc realloc

/*
 * @brief A wrapper over free functionality/ The function will free allocated memory.
 *
 */
#define _SaSi_PalMemFree free

#ifdef __cplusplus
}
#endif

#endif
