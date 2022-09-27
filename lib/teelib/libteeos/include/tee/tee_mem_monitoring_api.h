/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Create: 2012-12-31
 * Description: Header file of memory management api
 */

#ifndef TEE_MEM_MONITORING_API_H
#define TEE_MEM_MONITORING_API_H

#include <stdint.h>

/*
 * get heap usage of current TA
 *
 * @param show [IN] weather need to print result in log file
 *
 * @return percentage of heap usage
 */
uint32_t get_heap_usage(bool show);

#endif
