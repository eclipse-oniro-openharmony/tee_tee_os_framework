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

#ifndef __KEY_BUFFER_PLAT_H__
#define __KEY_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define PTR_TO_KEY_BUFFER(ptr)        ((KeyBuffer_s *)((uint32_t)(ptr)))
#define KEY_BUFFER_TO_PTR(pKeyBuffer) ((uint32_t)(pKeyBuffer))

#define INT_KEY_BUFF_SIZE_IN_BYTES 32
typedef uint8_t keyBuffer_t[INT_KEY_BUFF_SIZE_IN_BYTES];

enum dx_data_key_obj_api {
    DX_AES_API      = 0,
    DX_AES_API_INIT = 1,
    DX_AES_WRAP_API = 2,
    DX_AES_OEM_API  = 3,
    DX_AES_CMAC     = 4,
};

#endif /* __KEY_BUFFER_PLAT_H__ */
