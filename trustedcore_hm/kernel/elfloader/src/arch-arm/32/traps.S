/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader ivt table
 * Create: 2020-12
 */
#include <machine/assembler.h>

.text

.extern invalid_ivt_entry
.extern ivt_el1_sync

.macro ventry label
.align 7
    b       \label
.endm

.align 12
BEGIN_FUNC(elfloader_ivt)

END_FUNC(elfloader_ivt)
