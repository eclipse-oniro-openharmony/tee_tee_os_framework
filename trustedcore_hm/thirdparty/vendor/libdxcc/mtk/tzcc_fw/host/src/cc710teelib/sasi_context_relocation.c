/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_API

/* ! \file SaSi_context_relocation.c
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */
#include "sasi_context_relocation.h"
#include "ssi_pal_compiler.h"
#include "ssi_pal_mem.h"

/* Assume standard 4KB page size */
#define PAGE_SHIFT 12
#define PAGE_SIZE  (1 << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE - 1))
/* "natural" 4B alignment */
#define CONTEXT_ALIGNMENT_SHIFT 2
#define CONTEXT_ALIGNMENT_SIZE  (1 << CONTEXT_ALIGNMENT_SHIFT)
#define CONTEXT_ALIGNMENT_MASK  (~((1 << CONTEXT_ALIGNMENT_SHIFT) - 1))
#define CONTEXT_ALIGN(addr)     (((unsigned long)(addr) + CONTEXT_ALIGNMENT_SIZE - 1) & CONTEXT_ALIGNMENT_MASK)

#define IS_BUF_CROSS_PAGE(start, size) \
    (((unsigned long)(start) >> PAGE_SHIFT) < (((unsigned long)(start) + (size)-1) >> PAGE_SHIFT))

/* Context buffer properties */
/* this data is always saved at the original start of user context buffer */
typedef struct {
    uint32_t bufSize;   /* Original user buffer size in bytes */
    uint32_t ctxSize;   /* Contained context actual size in bytes */
    uint32_t ctxOffset; /* Byte offset of the contained context */
} SaSi_CtxBufProps_t;

SASI_PAL_COMPILER_ASSERT(sizeof(SaSi_CtxBufProps_t) == DX_CTX_BUFF_PROPS_SIZE_BYTES,
                         "sizeof(SaSi_CtxBufProps_t) should be equal to DX_CTX_BUFF_PROPS_SIZE_BYTES!");

/* !
 * Find a good offset in given buffer to accomodate given context size
 * without crossing a page boundary
 * Note: this function does not take into account the "bufProps" data
 *       that we locate in the buffer's start, so it should get
 *       bufferStart at the location that follows that data.
 *
 * \param bufferStart The pointer to the context buffer given by the user
 *                     (offseted to accomodate the bufProps data)
 * \param bufferSize The total size of pointed buffer
 * \param contextSize The size of a context to place in the buffer
 *
 * \return Offset of the context in the given buffer
 */
static unsigned long GetNonCrossingOffset(unsigned long bufferStart, unsigned long bufferSize,
                                          unsigned long contextSize)
{
    const unsigned long bufStartNextPage = (bufferStart + PAGE_SIZE) & PAGE_MASK;
    const unsigned long bufEndPage       = (bufferStart + bufferSize - 1) & PAGE_MASK;
    unsigned long goodLocation;

    if (bufStartNextPage > bufEndPage) {
        /* Buffer does not cross a page */
        /* Just assure alignment of buffer start */
        goodLocation = CONTEXT_ALIGN(bufferStart);
    } else if (bufStartNextPage == bufEndPage) {
        /* Buffer crosses one page boundary */
        /* Return part that can accomodate context */
        goodLocation = CONTEXT_ALIGN(bufferStart);
        if ((bufStartNextPage - goodLocation) < contextSize) {
            /* First part is too small, pick the start of the second page */
            goodLocation = bufEndPage; /* Page is always aligned... */
        }
    } else {
        /* Buffer crosses two page boundaries */
        /* Pick the start of the full page in the middle */
        goodLocation = bufStartNextPage;
    }

    return goodLocation - bufferStart;
}

/* !
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *SaSi_InitUserCtxLocation(void *bufferStart, unsigned long bufferSize, unsigned long contextSize)
{
    /* Buffer must accomodate the BufProps and 2*contextSize to
       assure at least contextSize bytes are not crossing page boundary */
    const unsigned long requested_buf_size = sizeof(SaSi_CtxBufProps_t) + 2 * contextSize;
    unsigned long contextOffset;
    void *contextStart;
    SaSi_CtxBufProps_t *bufProps = (SaSi_CtxBufProps_t *)bufferStart;
    /* Buffer properties are save at reserved space at buffer's start */

    /* Verify given sizes validity */
    if ((contextSize > PAGE_SIZE) || (bufferSize < requested_buf_size)) {
        return NULL;
    }

    /* Get good location (starting from buffer_ptr + sizeof(void*)) */
    contextOffset =
        GetNonCrossingOffset((unsigned long)bufferStart + sizeof(SaSi_CtxBufProps_t), bufferSize, contextSize);
    /* The actual offset is after the SaSi_CtxBufProps_t structure */
    contextOffset += sizeof(SaSi_CtxBufProps_t);
    /* Save buffer properties */
    bufProps->bufSize   = bufferSize;
    bufProps->ctxSize   = contextSize;
    bufProps->ctxOffset = contextOffset;

    contextStart = (void *)((unsigned long)bufferStart + contextOffset);
    return contextStart;
}

/* !
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *SaSi_GetUserCtxLocation(void *bufferStart)
{
    /* Calculate current context location based on offset in buffer props */
    SaSi_CtxBufProps_t *bufProps = (SaSi_CtxBufProps_t *)bufferStart;
    void *curContextLocation     = (void *)((unsigned long)bufferStart + bufProps->ctxOffset);
    unsigned long newContextOffset;
    void *newContextLocation;

    /* Verify current location */
    if (!IS_BUF_CROSS_PAGE(curContextLocation, bufProps->ctxSize)) {
        /* If context does not cross page boundary - keep it where it is */
        return curContextLocation;
    }

    /* If current location crosses a page boundary, find a new location */
    newContextOffset = GetNonCrossingOffset((unsigned long)bufferStart + sizeof(SaSi_CtxBufProps_t), bufProps->bufSize,
                                            bufProps->ctxSize);
    /* The actual offset is after the bufProps structure */
    newContextOffset += sizeof(SaSi_CtxBufProps_t);
    newContextLocation = (void *)((unsigned long)bufferStart + newContextOffset);

    /* memmove context from original location to new location */
    SaSi_PalMemMove(newContextLocation, curContextLocation, bufProps->ctxSize);
    /* update new location in start of buffer */
    bufProps->ctxOffset = newContextOffset;

    return newContextLocation;
}
