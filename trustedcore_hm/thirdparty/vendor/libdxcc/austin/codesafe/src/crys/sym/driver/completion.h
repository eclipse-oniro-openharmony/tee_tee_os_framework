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

#ifndef FW_COMPLETION_H
#define FW_COMPLETION_H

#include "completion_plat.h"
#include "compiler.h"

/* *****************************************************************************
 *                       MACROS
 * *************************************************************************** */
#define GET_FIFO_COMPLETION_TYPE(fifoItem) \
    BITFIELD_GET(fifoItem, FIFO_COMPLETION_TYPE_BIT_OFFSET, FIFO_COMPLETION_TYPE_BIT_SIZE)
#define GET_FIFO_AXI_COUNTER(fifoItem)        BITFIELD_GET(fifoItem, FIFO_AXI_COUNTER_BIT_OFFSET, FIFO_AXI_COUNTER_BIT_SIZE)
#define GET_FIFO_COMPLETION_TASK_ID(fifoItem) BITFIELD_GET(fifoItem, FIFO_TASK_ID_BIT_OFFSET, FIFO_TASK_ID_BIT_SIZE)

#define SET_FIFO_COMPLETION_TYPE(fifoItem, val) \
    BITFIELD_SET(fifoItem, FIFO_COMPLETION_TYPE_BIT_OFFSET, FIFO_COMPLETION_TYPE_BIT_SIZE, val)
#define SET_FIFO_AXI_COUNTER(fifoItem, val) \
    BITFIELD_SET(fifoItem, FIFO_AXI_COUNTER_BIT_OFFSET, FIFO_AXI_COUNTER_BIT_SIZE, val)
#define SET_FIFO_COMPLETION_TASK_ID(fifoItem, val) \
    BITFIELD_SET(fifoItem, FIFO_TASK_ID_BIT_OFFSET, FIFO_TASK_ID_BIT_SIZE, val)

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * This function calls the platform specific Completion Initializer function.
 *
 * \return int one of the error codes defined in err.h
 */
#define InitCompletion InitCompletionPlat

/* !
 * This function waits for current descriptor sequence completion.
 * The "WaitForSequenceCompletionPlat" function must implement by
 * the platform port layer.
 */
#define WaitForSequenceCompletion WaitForSequenceCompletionPlat

#endif /* FW_COMPLETION_H */
