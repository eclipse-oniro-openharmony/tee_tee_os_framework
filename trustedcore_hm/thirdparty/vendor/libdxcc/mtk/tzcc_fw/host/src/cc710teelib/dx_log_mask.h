/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _DX_LOG_MASK_H_
#define _DX_LOG_MASK_H_

/* CCLIB4 specific component masks */
#define DX_LOG_MASK_CCLIB           (1)
#define DX_LOG_MASK_SaSi_API        (1 << 1)
#define DX_LOG_MASK_SaSi_SYM_DRIVER (1 << 2)
#define DX_LOG_MASK_MLLI            (1 << 3)
#define DX_LOG_MASK_HW_QUEUE        (1 << 4)
#define DX_LOG_MASK_COMPLETION      (1 << 5)
#define DX_LOG_MASK_INFRA           (1 << 6)
#define DX_LOG_MASK_SaSi_LLF        (1 << 13)
#define DX_LOG_MASK_ASYM_ECC        (1 << 14)
#define DX_LOG_MASK_ASYM_RSA_DH     (1 << 15)
#define DX_LOG_MASK_ASYM_KDF        (1 << 16)
#define DX_LOG_MASK_ASYM_LLF        (1 << 17)
#define DX_LOG_MASK_ASYM_RND        (1 << 18)
#define DX_LOG_MASK_UTILS           (1 << 19)

#define DX_LOG_MASK_ASYM_SaSi_ALL                                                                       \
    (DX_LOG_MASK_ASYM_ECC || DX_LOG_MASK_ASYM_RSA_DH || DX_LOG_MASK_ASYM_KDF || DX_LOG_MASK_ASYM_LLF || \
     DX_LOG_MASK_ASYM_RND)

#endif /* _DX_LOG_MASK_H_ */
