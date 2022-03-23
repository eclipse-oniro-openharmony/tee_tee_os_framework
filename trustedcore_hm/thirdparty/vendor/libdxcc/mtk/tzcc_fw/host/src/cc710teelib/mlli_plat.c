/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_MLLI

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_pal_abort.h"
#include "cc_plat.h"
#include "completion.h"
#include "hw_queue.h"
#include "mlli.h"
#include "ssi_sram_map.h"

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */

/* SRAM workspace buffer for input and output MLLI tables per queue */
static DxSramAddr_t gMlliWorkspace = SASI_SRAM_MLLI_BASE_ADDR;

static void SetMlliStopEntry(int qid);

/* *****************************************************************************
 *            FUNCTIONS DECLARATIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function allocates IN/OUT MLLI tables in SRAM and appends the
 * "Last LLI" marker to the end of the IN/OUT tables. Each MLLI table size
 * is 1K + 8 bytes of the "last LLI" entry.
 *
 * \param none
 *
 * \return one of the error codes defined in err.h
 */
void InitMlli()
{
    uint32_t qid;

    SASI_PAL_LOG_INFO("Clear MLLI workspace at adr=0x%08X size=0x%08X\n", (unsigned int)gMlliWorkspace,
                      (unsigned int)(MAX_NUM_HW_QUEUES * MLLI_IN_OUT_BUF_SIZE));

    /* clear MLLI tables memory */
    _ClearSram(gMlliWorkspace, (MAX_NUM_HW_QUEUES * MLLI_IN_OUT_BUF_SIZE));
    for (qid = 0; qid < MAX_NUM_HW_QUEUES; qid++) {
        SetMlliStopEntry(qid);
    }
}

static void SetMlliStopEntry(int qid)
{
    DxSramAddr_t buffOfs = gMlliWorkspace;
    uint8_t i;

    /* Buffer offset to the begining of the corresponding queue by qid */
    buffOfs += (qid * MLLI_IN_OUT_BUF_SIZE);

    /* Buffer offset to last entry in input table */
    buffOfs += (MLLI_IN_OUT_BUF_SIZE - LLI_ENTRY_BYTE_SIZE);

    /* Set stop entry in last position of every MLLI table. */
    /* We have two tables (IN/OUT) per queue */
    for (i = 0; i < 2; i++) {
        SASI_PAL_LOG_INFO("Set stop entry at adr=0x%08X\n", (unsigned int)buffOfs);

        _WriteWordsToSram(buffOfs, 0x80000000, sizeof(uint32_t));
        /* Set offset to next table */
        buffOfs += MLLI_BUF_SIZE;
    }
}

DxSramAddr_t DX_GetMLLIWorkspace(void)
{
    return gMlliWorkspace;
}

uint32_t DX_GetIsMlliExternalAlloc(uint32_t qid)
{
    qid = qid;
    return 0;
}
