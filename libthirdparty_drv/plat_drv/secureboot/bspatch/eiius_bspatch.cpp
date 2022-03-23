/*
*  Copyright 2015 The Chromium OS Authors. All rights reserved.
*  Use of this source code is governed by a BSD-style license that can be
*  found in the LICENSE file.
*/

#include "bsdiff/bspatch.h"
#include "eiius_bspatch.h"
#include <bzlib.h>

int eiius_bspatch(const uint8_t* old_data,
                         size_t old_size,
                         const uint8_t* patch_data,
                         size_t patch_size,
                         const sink_func sink)
{
    int ret = 0;
    BZ2_set_multiplier(EIIUS_BSPATCH_BUF_SIZE);
    bsdiff::bspatch(old_data,old_size,patch_data,patch_size,sink);
    BZ2_set_multiplier(MODEM_BSPATCH_BUF_SIZE);
    return ret;
}
