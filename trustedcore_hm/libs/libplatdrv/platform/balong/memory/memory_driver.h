#ifndef MEMORY_DRIVER_H
#define MEMORY_DRIVER_H

#include <product_config.h>
#include <bsp_shared_ddr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define mem_err(fmt, ...) (uart_printf_func("memory: %s " fmt, __FUNCTION__, ##__VA_ARGS__))

#define MEM_OK    (0)
#define MEM_ERROR (-1)
#ifdef CONFIG_SHARED_MEMORY
typedef struct {
    const char name[32];
    unsigned int size;
    unsigned int offset;
    unsigned int magic;
}mem_mgr_node_info_s;

typedef struct {
    mem_mgr_node_info_s *dts_info;
    phy_addr_t base_addr;
    void *virt_base_addr;
    unsigned int size;
    unsigned int dts_info_size;
} mem_mgr_info_s;

typedef struct {
    unsigned int addr;
    unsigned int size;
}shm_layout_s;

// 以下添加各版本一致且不改变的非安全共享内存offset及size
#define SHM_DTSINFO_SIZE 0x1000
#else
struct share_mem_ctrl {
    const char *name;
    unsigned long base_addr;
    unsigned int size;
};
#endif
#ifdef __cplusplus
}
#endif

#endif
