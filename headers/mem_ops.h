#ifndef MEM_OPS_H
#define MEM_OPS_H

#include <stdint.h>
#include <stddef.h>
#include <tee_uuid.h>

#define STATPROC_NAME_MAX 64
#define PATHNAME_MAX 256
#define STATPROC_MAX 100

struct stat_proc_mem {
    char name[STATPROC_NAME_MAX];
    uint32_t mem;
    uint32_t mem_max;
    uint32_t mem_limit;
};

struct stat_mem_info {
    uint32_t total_mem;
    uint32_t mem;
    uint32_t free_mem;
    uint32_t free_mem_min;
    uint32_t proc_num;
    struct stat_proc_mem proc_mem[STATPROC_MAX];
};

int32_t task_map_ns_phy_mem(uint32_t task_id, uint64_t phy_addr, uint32_t size, uint64_t *virt_addr);

int32_t task_unmap(uint32_t task_id, uint64_t virt_addr, uint32_t size);

void *alloc_sharemem_aux(const struct tee_uuid *uuid, uint32_t size);

uint32_t free_sharemem(void *addr, uint32_t size);

int32_t map_sharemem (uint32_t src_task, uint64_t vaddr, uint64_t size, uint64_t *vaddr_out);

uint64_t virt_to_phys(uintptr_t vaddr);  

int32_t dump_mem_info(struct stat_mem_info *info, int print_history);

#endif
