#ifndef __TEE_FACE_RECOGNIZE_H__
#define __TEE_FACE_RECOGNIZE_H__

int fr_secure_memory_map(paddr_t phy_addr, unsigned int size,
			 unsigned int *virt_addr, unsigned int secure_mode, unsigned int cache_mode);
int fr_secure_memory_unmap(unsigned int virt_addr, unsigned int size);
int fr_is_secure_memory(paddr_t addr, unsigned int size,
			unsigned int protect_id);
void fr_flush_cache(unsigned int start, unsigned int end);
int fr_sion_pool_flag_set(unsigned int type);
int fr_sion_pool_flag_unset(unsigned int type);
unsigned int  fr_read_current_time(void);
int fr_get_static_phy_addr(unsigned int *addr, unsigned int type, unsigned int index, unsigned int size);

#endif

