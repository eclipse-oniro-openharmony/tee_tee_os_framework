/*
 * Copyright (c) 2019 MediaTek Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __MTK_TEE_DRAPI_H__
#define __MTK_TEE_DRAPI_H__

#include <drStd.h>

#define drDbgPrintf uart_printf_func
extern void v7_dma_flush_range(unsigned long start, unsigned long end);

uint32_t dr_api_map_io(uint64_t paddr, size_t size, uint32_t mapflag, void **vaddr);
uint32_t dr_api_unmap_io(uint64_t paddr, const void *vaddr);
uint32_t dr_api_map_physical_buffer(uint64_t paddr, size_t size, uint32_t mapflag, void **vaddr);
uint32_t dr_api_unmap_buffer(void *vaddr, uint32_t size);
uint32_t dr_api_cache_data_clean_all(unsigned long start, unsigned long end);
#endif
