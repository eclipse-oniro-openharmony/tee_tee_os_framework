/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Init function in check
 * Create: 2020-02-20
 */
#include "param_check.h"
#include <sre_typedef.h>

struct buffer_context {
    uint32_t buf_size;
    uint32_t ctx_size;
    uint32_t ctx_offset;
};

#define CHECK_BUFFER_OK 1
#define CHECK_BUFFER_ERR 0
#define PAGE_SHIFT 12U
#define PAGE_SIZE  (1U << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE - 1U))

#define CONTEXT_ALIGNMENT_SHIFT 2U
#define CONTEXT_ALIGNMENT_SIZE  (1U << CONTEXT_ALIGNMENT_SHIFT)
#define CONTEXT_ALIGNMENT_MASK  (~((1U << CONTEXT_ALIGNMENT_SHIFT) - 1U))
#define context_align(addr)     (((uint32_t)(addr) + CONTEXT_ALIGNMENT_SIZE - 1U) & CONTEXT_ALIGNMENT_MASK)

#define is_buf_cross_page(start, size) \
    (((uint32_t)(start) >> PAGE_SHIFT) < (((uint32_t)(start) + (size) - 1U) >> PAGE_SHIFT))

static uint32_t get_cross_offset(uint32_t buffer_start, uint32_t buffer_size,
                                 uint32_t context_size)
{
    const uint32_t buf_start_next_page = (buffer_start + PAGE_SIZE) & PAGE_MASK;
    const uint32_t buf_end_page = (buffer_start + buffer_size - 1) & PAGE_MASK;
    uint32_t end_location;
    uint32_t buffer_offset;
    if (buf_start_next_page > buf_end_page) {
        end_location = context_align(buffer_start);
    } else if (buf_start_next_page == buf_end_page) {
        end_location = context_align(buffer_start);
        if ((buf_start_next_page - end_location) < context_size)
            end_location = buf_end_page;
    } else {
        end_location = buf_start_next_page;
    }
    buffer_offset = end_location - buffer_start;
    return buffer_offset;
}

int32_t check(const void *buffer_start, uint32_t buffer_size)
{
    struct buffer_context *buf_props = NULL;
    uintptr_t cur;
    uint32_t con_offset;
    uintptr_t new_offset;
    uintptr_t buf_start = (uintptr_t)buffer_start;
    buf_props = (struct buffer_context *)buffer_start;

    if (buf_props == NULL)
        return CHECK_BUFFER_ERR;

    cur = (uintptr_t)(buf_start + buf_props->ctx_offset);
    if (is_buf_cross_page(cur, buf_props->ctx_size) == 0) {
        if (cur > (uintptr_t)(buf_start + buffer_size - buf_props->ctx_size) || buf_start > cur)
            return CHECK_BUFFER_ERR;
    }

    con_offset = get_cross_offset(buf_start + sizeof(*buf_props), buf_props->buf_size, buf_props->ctx_size);
    con_offset += sizeof(*buf_props);
    new_offset = (uintptr_t)(buf_start + con_offset);
    if (new_offset > (uintptr_t)(buf_start + buffer_size) || buf_start > new_offset)
        return CHECK_BUFFER_ERR;

    return CHECK_BUFFER_OK;
}
