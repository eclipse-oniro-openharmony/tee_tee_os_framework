/*
 * hisilicon ISP driver, hisp_mem.h
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#ifndef _KIRIN_ISP_HISP_LOAD_H_
#define _KIRIN_ISP_HISP_LOAD_H_

#include <sre_typedef.h> // UINT32

UINT32 hisp_sec_text_img_copy(UINT32 sfd, UINT32 size);
UINT32 hisp_sec_data_img_copy(UINT32 sfd, UINT32 size);
#endif
