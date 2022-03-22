/************************************************************************************************
*
*  FileName:        zmalloc.c
*  Description:     zlib malloc for secureboot
*  Author:
*  Version:         v1.0
*  Date:
*  History:
*
*  Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
*
*************************************************************************************************/
#include <zlib.h>
#include <zutil.h>
#include <inftrees.h>
#include <inflate.h>
#include "tee_log.h"

#define WINDOW_SIZE_32K 32768
static struct inflate_state FAR g_state;
static char g_work_window[WINDOW_SIZE_32K];//32k
voidpf ZLIB_INTERNAL zcalloc (opaque, items, size)
    voidpf opaque;
    unsigned items;
    unsigned size;
{
    (void)opaque;
    (void)items;
    if (size == sizeof(struct inflate_state)) {
        return (voidpf)(&g_state);
    } else if (size == sizeof(unsigned char)) {
        if (size * items > WINDOW_SIZE_32K) {
            tloge("error, malloc window size over 32k.\n");
            return NULL;
        }
        return (voidpf)(&g_work_window[0]);
    }
    return NULL;
}

void ZLIB_INTERNAL zcfree (opaque, ptr)
    voidpf opaque;
    voidpf ptr;
{
    (void)opaque;
    (void)ptr;
}
