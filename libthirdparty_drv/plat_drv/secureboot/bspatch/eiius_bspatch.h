/*
* Copyright 2015 The Chromium OS Authors. All rights reserved.
* Use of this source code is governed by a BSD-style license that can be
* found in the LICENSE file.
*/

#ifndef _EIIUS_BSPATCH_H_
#define _EIIUS_BSPATCH_H_
#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <types.h>

#define EIIUS_BSPATCH_BUF_SIZE (100000)
#define MODEM_BSPATCH_BUF_SIZE (1000)

typedef size_t (*sink_func)(const uint8_t* src_addr, size_t size);
int eiius_bspatch(const uint8_t* old_data,
			 size_t old_size,
			 const uint8_t* patch_data,
			 size_t patch_size,
			 const sink_func sink);

#ifdef  __cplusplus
}
#endif  /* end of __cplusplus */

#endif  // _BSDIFF_FILE_H_
