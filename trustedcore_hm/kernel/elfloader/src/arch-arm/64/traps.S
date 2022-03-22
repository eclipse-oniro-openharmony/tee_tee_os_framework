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
    ventry  invalid_ivt_entry           // Synchronous EL1t
    ventry  invalid_ivt_entry           // IRQ EL1t
    ventry  invalid_ivt_entry           // FIQ EL1t
    ventry  invalid_ivt_entry           // SError EL1t

    ventry  ivt_el1_sync                // Synchronous EL1h
    ventry  invalid_ivt_entry           // IRQ EL1h
    ventry  invalid_ivt_entry           // FIQ EL1h
    ventry  invalid_ivt_entry           // SError EL1h

    ventry  invalid_ivt_entry           // Synchronous 64-bit EL0
    ventry  invalid_ivt_entry           // IRQ 64-bit EL0
    ventry  invalid_ivt_entry           // FIQ 64-bit EL0
    ventry  invalid_ivt_entry           // SError 64-bit EL0

    ventry  invalid_ivt_entry           // Synchronous 32-bit EL0
    ventry  invalid_ivt_entry           // IRQ 32-bit EL0
    ventry  invalid_ivt_entry           // FIQ 32-bit EL0
    ventry  invalid_ivt_entry           // SError 32-bit EL0

END_FUNC(elfloader_ivt)
