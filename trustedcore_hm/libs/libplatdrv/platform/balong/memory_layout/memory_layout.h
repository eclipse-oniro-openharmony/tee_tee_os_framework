#ifndef MEMORY_LAYOUT_H
#define MEMORY_LAYOUT_H

#include <bsp_memory_layout.h>
#include <sre_typedef.h>

#define NAME_MAX_LEN 16

#define mem_err(fmt, ...) (uart_printf_func("memory: %s " fmt, __FUNCTION__, ##__VA_ARGS__))

#define MEM_OK    0
#define MEM_ERROR (-1)

typedef struct {
    u64 addr; /* 内存首地址 */
    u32 size; /* 内存大小 */
    char name[NAME_MAX_LEN]; /* 内存名称 */
}mem_node_info;

typedef struct {
    unsigned int size; /* 内存信息总大小 */
    mem_node_info *memory_info; /* 内存详细信息 */
}mem_layout;

int bsp_memory_layout_init(void);

#endif
