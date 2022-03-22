/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: store tee log
 * Create: 2019-08-20
 */

#ifndef PLATFORM_PLATFORM_GENERIC_H
#define PLATFORM_PLATFORM_GENERIC_H

#include "sys_generic.h"
#include "serial_generic.h"

/*
 * store tee log to DUMP_MEM_START
 * Total 500k:480k for tee log and 20k for secure page table
 */
#define DUMP_SECURE_PAGE_TABLE_SIZE (20 * 1024)
#define DUMP_MEM_RESERVE_SIZE   156 /* for trustedcore info, for example version */
#define DUMP_MEM_STRUCT_SIZE    64 /* for record the real write addr or write ring-buffer times */
#define DUMP_WCD_BUFFER_SIZE    (5 * 1024)

#endif
