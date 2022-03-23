/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

/*! \file cc_context_relocation.c
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */
#include "cc_context_relocation.h"
#include "cc_pal_compiler.h"
#include "cc_pal_mem.h"
#include "cc_hash_defs.h"

/* Assume standard 4KB page size */
#define PAGE_SHIFT 12
#define PAGE_SIZE (1<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
/* "natural" 4B alignment */
#define CONTEXT_ALIGNMENT_SHIFT 2
#define CONTEXT_ALIGNMENT_SIZE (1<<CONTEXT_ALIGNMENT_SHIFT)
#define CONTEXT_ALIGNMENT_MASK (~((1<<CONTEXT_ALIGNMENT_SHIFT) - 1))
#define CONTEXT_ALIGN(addr) \
    (((unsigned long)(addr)+CONTEXT_ALIGNMENT_SIZE-1) & CONTEXT_ALIGNMENT_MASK)

#define IS_BUF_CROSS_PAGE(start, size) \
    (((unsigned long)(start) >> PAGE_SHIFT) < (((unsigned long)(start) + (size) - 1) >> PAGE_SHIFT))

#define MAX_BUFF_SIZE (CC_HASH_USER_CTX_SIZE_IN_WORDS * 4)
/* Context buffer properties */
/* this data is always saved at the original start of user context buffer */
typedef struct {
	uint32_t bufSize;	/* Original user buffer size in bytes */
	uint32_t ctxSize;	/* Contained context actual size in bytes */
	uint32_t ctxOffset;/* Byte offset of the contained context */
}CCCtxBufProps_t;

CC_PAL_COMPILER_ASSERT(sizeof(CCCtxBufProps_t) == CC_CTX_BUFF_PROPS_SIZE_BYTES, "sizeof(CCCtxBufProps_t) should be equal to CC_CTX_BUFF_PROPS_SIZE_BYTES!");


/*!
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
static unsigned long GetNonCrossingOffset(unsigned long bufferStart,
					  unsigned long bufferSize,
					  unsigned long contextSize)
{
	const unsigned long bufStartNextPage =
	(bufferStart + PAGE_SIZE) & PAGE_MASK;
	const unsigned long bufEndPage =
	(bufferStart + bufferSize - 1) & PAGE_MASK;
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

/*!
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *RcInitUserCtxLocation(void *bufferStart,
			     unsigned long bufferSize,
			     unsigned long contextSize)
{
	/* Buffer must accomodate the BufProps and 2*contextSize to
	   assure at least contextSize bytes are not crossing page boundary */
	const unsigned long requested_buf_size =
		sizeof(CCCtxBufProps_t) + 2*contextSize;
	unsigned long contextOffset;
	void *contextStart;
	CCCtxBufProps_t *bufProps = (CCCtxBufProps_t *)bufferStart;
	/* Buffer properties are save at reserved space at buffer's start */

	/* Verify given sizes validity*/
	if ((contextSize > PAGE_SIZE) || (bufferSize < requested_buf_size)) {
		return NULL;
	}

	/* Get good location (starting from buffer_ptr + sizeof(void*))*/
	contextOffset = GetNonCrossingOffset((unsigned long)bufferStart +
					     sizeof(CCCtxBufProps_t),
					     bufferSize, contextSize);
	/* The actual offset is after the CCCtxBufProps_t structure */
	contextOffset += sizeof(CCCtxBufProps_t);
	/* Save buffer properties */
	bufProps->bufSize = bufferSize;
	bufProps->ctxSize = contextSize;
	bufProps->ctxOffset = contextOffset;

	contextStart = (void*)((unsigned long)bufferStart + contextOffset);
	return contextStart;
}

/*!
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *RcGetUserCtxLocation(void *bufferStart)
{
	/* Calculate current context location based on offset in buffer props */
	CCCtxBufProps_t *bufProps = (CCCtxBufProps_t *)bufferStart;
	if (bufProps->bufSize > MAX_BUFF_SIZE || bufProps->ctxSize > bufProps->bufSize ||
           bufProps->ctxOffset > bufProps->bufSize - bufProps->ctxSize) {
		return NULL;
	}

	void *curContextLocation = (void *)
				   ((unsigned long)bufferStart + bufProps->ctxOffset);
	unsigned long newContextOffset;
	void *newContextLocation;

	/* Verify current location */
	if (!IS_BUF_CROSS_PAGE(curContextLocation, bufProps->ctxSize)) {
		/* If context does not cross page boundary - keep it where it is */
		return curContextLocation;
	}

	/* If current location crosses a page boundary, find a new location */
	newContextOffset = GetNonCrossingOffset(
					       (unsigned long)bufferStart + sizeof(CCCtxBufProps_t),
					       bufProps->bufSize, bufProps->ctxSize);
	/* The actual offset is after the bufProps structure */
	newContextOffset += sizeof(CCCtxBufProps_t);
	newContextLocation = (void*)((unsigned long)bufferStart + newContextOffset);

	/* memmove context from original location to new location */
	CC_PalMemMove(newContextLocation, curContextLocation, bufProps->ctxSize);
	/* update new location in start of buffer */
	bufProps->ctxOffset = newContextOffset;

	return newContextLocation;
}


/*!
 * Just return the context address in the given buffer
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *GetUserCtxLocation(void *bufferStart)
{
	/* Calculate current context location based on offset in buffer props */
	CCCtxBufProps_t *bufProps = (CCCtxBufProps_t *)bufferStart;

	return (void *)((unsigned long)bufferStart + bufProps->ctxOffset);
}
