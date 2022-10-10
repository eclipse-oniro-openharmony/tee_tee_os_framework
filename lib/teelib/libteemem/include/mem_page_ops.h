/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: paddr definition and PAGE operation macro
 * Create: 2019-11-29
 */
#ifndef LIBTEEMEM_MEM_PAGE_OPS_H
#define LIBTEEMEM_MEM_PAGE_OPS_H

#include <sre_typedef.h>

#ifndef ALIGN_UP
#define ALIGN_UP(x, align) (((x) + ((align)-1)) & ~((align)-1))
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, align) ((x) & ~((align)-1))
#endif

/* Physical address in the system */
#ifndef PADDR_T_DEFINED
typedef uint64_t paddr_t;
#define PADDR_T_DEFINED
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (1u << PAGE_SHIFT)
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1)) /* 0xFFFFF000 */
#endif

#ifndef PAGE_MASK_64BIT
#define PAGE_MASK_64BIT 0xFFFFFFF000
#endif

#ifndef PAGE_OFFSET_MASK
#define PAGE_OFFSET_MASK (PAGE_SIZE - 1) /* 0xFFF */
#endif

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) ALIGN_UP((x), PAGE_SIZE)
#endif
#ifndef PAGE_ALIGN_DOWN
#define PAGE_ALIGN_DOWN(x) ALIGN_DOWN((x), PAGE_SIZE)
#endif

#ifndef IS_PAGE_ALIGNED
#define IS_PAGE_ALIGNED(addr) (((addr) & PAGE_OFFSET_MASK) == 0)
#endif

#endif /* LIBTEEMEM_MEM_PAGE_OPS_H */
