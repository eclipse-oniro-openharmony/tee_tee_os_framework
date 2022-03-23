/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef FW_HW_QUEUE_H
#define FW_HW_QUEUE_H

#include "hw_queue_plat.h"
#include "completion_plat.h"
#include "hw_queue_defs.h"
#include "hw_queue_plat.h"
#include "ssi_compiler.h"
#include "completion.h"

/* Wrapper for HW_QUEUE_POLL_QUEUE_UNTIL_EMPTY() to allow fallback to blocking
   with WaitForSequenceCompletion after polling for some time.
   This helps avoiding hw queue getting stuck in case of a context switch when
   lock bit is on. This is relevant only for multi-task environments (i.e.,
   when openrtos is running) */
#define HW_QUEUE_POLL_TIMEOUT (30)
#define HW_QUEUE_WAIT_UNTIL_EMPTY(_qid)                                    \
    while (!HW_QUEUE_POLL_QUEUE_UNTIL_EMPTY(qid, HW_QUEUE_POLL_TIMEOUT)) { \
        /* Not empty after polling for a while -                           \
           go for blocking to allow context switch */                      \
        WaitForSequenceCompletion();                                       \
    }

/*
 Locks HW queue sequencer.
 This API must use in platforms that should avoid
 descriptors sequence interleaving.
*/
#define HW_QUEUE_LOCK() _HW_QUEUE_LOCK()

/*
 Unlocks HW queue sequencer.
 This API must use in platforms that should avoid
 descriptors sequence interleaving.
*/
#define HW_QUEUE_UNLOCK() _HW_QUEUE_UNLOCK()

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * This function initializes a HW queue, sets up the watermark event and
 * the mutex related to that queue.
 *
 * \return int one of the error codes defined in err.h
 */
int InitHWQueue(void) SASI_ICACHE_FUNCTION;

/* !
 * This function adds a HW descriptor sequence to a HW queue. If not
 * enough free slot are available in the HW queue, the function will set
 * up the "Water Mark" register and wait on an event until free slots are
 * available. This function will always mark the last descriptor in the
 * sequence as "last", even if the "last" bit was left clear. The caller
 * can leave the "Ack needed" field un-initialized. This function will
 * set the "Ack needed" field in each descriptor to either zero or to the
 * CounterId for the last descriptor.
 * The caller can indirectly control whether the function will block until
 * the descriptor is complete or return without blocking for asynchronous
 * mode. This is done by referring to a completion counter ID that is
 * defined as "external completion" or "internal completion".
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param descSeq A pointer to a HW descriptor sequence. All descriptor
 *              structures are 5 words long according to [CC54-DESC].
 *              The sequence buffer is a group of word aligned sequential
 *              descriptor buffers.
 * \param seqLen The length of the sequence (in descriptor units - 5
 *             words). The length must be greater than 0 and less
 *             than the HW queue size.
 */
void AddHWDescSequence(int qid, HwDesc_s *descSeq);

/* !
 * This function adds a dummy completion HW descriptor to a HW queue in
 * order to later on signal an internal completion event.
 * The dummy HW completion descriptor is created by using the DMA bypass
 * mode with zero size DIN and DOUT data. A counter ID related to the qid is always
 * used to setup the "Ack required" field in the HW descriptor.
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param taskId Task ID as set by vTaskSetCurrentTaskTag().
 * \param completionCtx Completion context contains the required information for completion (platform specific).
 */
void AddCompletionDesc(int qid, uint32_t tTaskId, void *completionCtx);

/* !
 * This function adds a set register HW descriptor to a HW queue.
 * Note: the caller must make sure that the new register value does not affect
 * the other HW queue (if exists).
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param address The register address.
 * \param value The register value.
 */
void AddSetRegisterValueDesc(int qid, uint32_t address, uint32_t value);

#endif /* FW_HW_QUEUE_H */
