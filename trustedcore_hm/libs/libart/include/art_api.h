/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for ART(Anti-Rollback Token) api.
 * Author : c00301810
 * Create: 2020/03/21
 */

#ifndef __ART_API_H__
#define __ART_API_H__

#include <tee_internal_api.h>

/*
 * @brief      : Allocate an ART counter slot for the caller(Current TA).
 *
 * @param[in]  : void
 * @param[out] : total_counters : total counter number of the allocated slot.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTAllocSlot(uint32_t *total_counters);

/*
 * @brief      : Read the value of an ART slot counter.
 *
 * @param[in]  : counter_id : counter ID, from 0 to total_counters-1.
 * @param[out] : counter_value : Counter value.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTReadCounter(uint32_t counter_id, uint32_t *counter_value);

/*
 * @brief      : Increase the value of an ART slot counter.
 *
 * @param[in]  : counter_id : counter ID, from 0 to total_counters-1.
 * @param[out] : counter_value : Counter value.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTIncreaseCounter(uint32_t counter_id, uint32_t *counter_valuer);

#endif /* __ART_API_H__ */
