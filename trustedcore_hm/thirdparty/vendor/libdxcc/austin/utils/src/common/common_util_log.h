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

#ifndef _UTIL_LOG_H
#define _UTIL_LOG_H

#include "stdio.h"

#define DX_COMMON_OK   0
#define WORD_BYTE_SIZE (sizeof(uint32_t))

#define UTIL_LOG_ERR(format, args...) fprintf(stderr, "%s(): " format, __FUNCTION__, ##args)

#ifdef UTIL_DEBUG
#define UTIL_LOG_INFO UTIL_LOG_ERR
#define UTIL_LOG_BYTE_BUFF(str, buff, size)                                 \
    {                                                                       \
        int i                   = 0;                                        \
        unsigned long buff_addr = (unsigned long)buff;                      \
        UTIL_LOG_ERR("\nprinting %s, %lu bytes", str, (unsigned long)size); \
        for (i = 0; i < size; i++) {                                        \
            if (!(i % 16)) {                                                \
                fprintf(stderr, "\n");                                      \
            }                                                               \
            fprintf(stderr, " 0x%02X ", *((unsigned char *)buff_addr + i)); \
        }                                                                   \
        fprintf(stderr, "\n");                                              \
    }
#define UTIL_LOG_WORD_BUFF(str, buff, wordSize)                                 \
    {                                                                           \
        int i                   = 0;                                            \
        unsigned long buff_addr = (unsigned long)buff;                          \
        UTIL_LOG_ERR("\nprinting %s, %lu words", str, (unsigned long)wordSize); \
        for (i = 0; i < wordSize; i++) {                                        \
            if (!(i % 4)) {                                                     \
                fprintf(stderr, "\n");                                          \
            }                                                                   \
            fprintf(stderr, " 0x%08lX ", *((unsigned long *)buff_addr + i));    \
        }                                                                       \
        fprintf(stderr, "\n");                                                  \
    }
#else
#define UTIL_LOG_INFO(format...) \
    do {                         \
    } while (0)
#define UTIL_LOG_BYTE_BUFF(str, buff, size) \
    do {                                    \
    } while (0)
#define UTIL_LOG_WORD_BUFF(str, buff, size) \
    do {                                    \
    } while (0)
#endif

#define UTIL_REVERSE_WORD_ORDER(buff, buffSize) \
    {                                           \
        uint32_t i      = 0;                    \
        uint8_t tmpByte = 0;                    \
        if (buffSize % WORD_BYTE_SIZE) {        \
            memset(buff, 0, buffSize);          \
        } else {                                \
            while ((i + 3) < buffSize) {        \
                tmpByte     = buff[i + 3];      \
                buff[i + 3] = buff[i];          \
                buff[i]     = tmpByte;          \
                tmpByte     = buff[i + 2];      \
                buff[i + 2] = buff[i + 1];      \
                buff[i + 1] = tmpByte;          \
                i += 4;                         \
            }                                   \
        }                                       \
    }

#endif
