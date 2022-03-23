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

#ifndef TEE_COMPLETION_PLAT_H
#define TEE_COMPLETION_PLAT_H

#include "dx_pal_types.h"

/* *****************************************************************************
 *                DEFS
 * *************************************************************************** */
#define MAX_COMPLETION_COUNTERS           (MAX_NUM_HW_QUEUES)
#define QID_TO_COMPLETION_COUNTER_ID(qid) (qid)

/* Fifo size must be a power of 2 */
#define COMPLETION_FIFO_LEN 64

#define FIFO_COMPLETION_TYPE_BIT_OFFSET 0
#define FIFO_COMPLETION_TYPE_BIT_SIZE   2

#define FIFO_AXI_COUNTER_BIT_OFFSET 2
#define FIFO_AXI_COUNTER_BIT_SIZE   4

#define FIFO_TASK_ID_BIT_OFFSET 6
#define FIFO_TASK_ID_BIT_SIZE   2

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

typedef enum CompletionType {
    COMPLETION_EXTERNAL = 1, /* Must be equal to one */
    COMPLETION_INVALID  = 2,
    COMPLETION_INTERNAL = INT8_MAX, /* No internal completion but must be defined */
    COMPLETION_END      = INT8_MAX,
} CompletionType_t;

/* !
 * This function initializes the completion counter event, clears the
 * state structure and sets completion counter "0" as the first available
 * counter to be used when calling "AllocCounter".
 *
 * \return int one of the error codes defined in err.h
 */
int InitCompletionPlat(void);

/* !
 * This function waits for current descriptor sequence completion.
 */
void WaitForSequenceCompletionPlat(void);

/* !
 * This function adds a completion report to the completion fifo.
 *
 * \param qid The queue id.
 * \param taskId Task ID to be signaled upon completion.
 * \param pCompletionType The completion Type.
 * \param axiWriteCount AXI transactions counter from previous completion report.
 */
void CompletionFifoInsert(int qid, uint32_t taskId, CompletionType_t *pCompletionType, uint32_t axiWriteCount);

/* !
 * This function remove a completion report to the completion fifo.
 *
 * \param qid The queue id.
 * \param taskId Task ID to be signaled upon completion.
 * \param pCompletionType The completion Type.
 * \param axiWriteCount AXI transactions counter from previous completion report.
 */
void CompletionFifoRemove(int qid, uint32_t *taskId, CompletionType_t *pCompletionType, uint32_t *axiWriteCount);

/* !
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void);

/* !
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void);

#endif /* TEE_COMPLETION_PLAT_H */
