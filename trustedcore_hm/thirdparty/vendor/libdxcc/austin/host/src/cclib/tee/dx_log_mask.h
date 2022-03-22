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

#ifndef _DX_LOG_MASK_H_
#define _DX_LOG_MASK_H_

/* CCLIB4 specific component masks */
#define DX_LOG_MASK_CCLIB           (1)
#define DX_LOG_MASK_CRYS_API        (1 << 1)
#define DX_LOG_MASK_CRYS_SYM_DRIVER (1 << 2)
#define DX_LOG_MASK_MLLI            (1 << 3)
#define DX_LOG_MASK_HW_QUEUE        (1 << 4)
#define DX_LOG_MASK_COMPLETION      (1 << 5)
#define DX_LOG_MASK_INFRA           (1 << 6)
#define DX_LOG_MASK_CRYS_LLF        (1 << 13)
#define DX_LOG_MASK_ASYM_ECC        (1 << 14)
#define DX_LOG_MASK_ASYM_RSA_DH     (1 << 15)
#define DX_LOG_MASK_ASYM_KDF        (1 << 16)
#define DX_LOG_MASK_ASYM_LLF        (1 << 17)
#define DX_LOG_MASK_ASYM_RND        (1 << 18)
#define DX_LOG_MASK_SECURE_BOOT     (1 << 19)

#define DX_LOG_MASK_ASYM_CRYS_ALL                                                                       \
    (DX_LOG_MASK_ASYM_ECC || DX_LOG_MASK_ASYM_RSA_DH || DX_LOG_MASK_ASYM_KDF || DX_LOG_MASK_ASYM_LLF || \
     DX_LOG_MASK_ASYM_RND)

#endif /* _DX_LOG_MASK_H_ */
