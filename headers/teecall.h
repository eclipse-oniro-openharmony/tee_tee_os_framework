#ifndef SYS_TEECALL_H
#define SYS_TEECALL_H

#include <stdbool.h>

typedef struct {
#if defined(CONFIG_ARCH_AARCH64)
    uint64_t params_stack[8];
#else
    uint32_t params_stack[8];
#endif
} __attribute__((packed)) kernel_shared_varibles_t;

int32_t tee_pull_kernel_variables(const kernel_shared_varibles_t *pVar);

void tee_push_rdr_update_addr(uint64_t addr, uint32_t size, bool is_cache_mem,
                              const char *chip_type_buff, uint32_t buff_len);
							  
int32_t teecall_cap_time_sync(uint32_t seconds, uint32_t mills);

#endif
