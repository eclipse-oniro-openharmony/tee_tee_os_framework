/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __KEY_BUFFER_PLAT_H__
#define __KEY_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define PTR_TO_KEY_BUFFER(ptr)        ((KeyBuffer_s *)((uint32_t)(ptr)))
#define KEY_BUFFER_TO_PTR(pKeyBuffer) ((uint32_t)(pKeyBuffer))

#define INT_KEY_BUFF_SIZE_IN_BYTES 32
typedef uint8_t keyBuffer_t[INT_KEY_BUFF_SIZE_IN_BYTES];

enum SaSiDataKeyObjApi_t {
    SASI_AES_API      = 0,
    SASI_AES_API_INIT = 1,
    SASI_AES_WRAP_API = 2,
    SASI_AES_OEM_API  = 3,
    SASI_AES_CMAC     = 4,
};

#endif /* __KEY_BUFFER_PLAT_H__ */
