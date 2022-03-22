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

#ifndef _NVM_ERROR_H
#define _NVM_ERROR_H
#ifdef __cplusplus
extern "C" {
#endif

#define DX_NVM_INV_INPUT_PARAM    DX_NVM_BASE_ERROR + 0x00000001
#define DX_NVM_OEM_HASH_ECC_ERROR DX_NVM_BASE_ERROR + 0x00000002
#define DX_NVM_ZERO_AES_KEY_ERROR DX_NVM_BASE_ERROR + 0x00000003

#ifdef __cplusplus
}
#endif

#endif
