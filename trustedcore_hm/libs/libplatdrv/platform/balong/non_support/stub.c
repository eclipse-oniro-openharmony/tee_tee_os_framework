#include "stdint.h"
#define STUB_NOT_SUPPORT() \
	do {\
		uart_printf_func("MBB [%s]ERROR: not support this func\n", __func__); \
		return -1; \
	} while (0)


typedef long long paddr_t;
int SECURE_ISSecureMemory(paddr_t addr, unsigned int size)
{
	STUB_NOT_SUPPORT();
}
int SECURE_TEE_Unmap(unsigned int virt_addr, unsigned int size)
{
	STUB_NOT_SUPPORT();
}
int SECURE_TEE_Mmap(paddr_t phy_addr , unsigned int size,
    unsigned int *virt_addr,unsigned int secure_mode, unsigned int cache_mode)
{
	STUB_NOT_SUPPORT();
}
unsigned int initSecureContentPath(paddr_t addr, unsigned int size) {
	STUB_NOT_SUPPORT();
}
unsigned int terminateSecureContentPath(unsigned int addr, unsigned int size) {
	STUB_NOT_SUPPORT();
}
unsigned int isSecureContentMemory(paddr_t addr, unsigned int size) {
	STUB_NOT_SUPPORT();
}

int get_vsim_sharemem(unsigned int *addr, unsigned int *size) {
	STUB_NOT_SUPPORT();
}

int set_dynmem_config(struct dynion_mem_k  *memconfig,int type) {
	STUB_NOT_SUPPORT();
}

extern int SRE_GetTeePlatRootKey(uint8_t *key_tpr, uint32_t size) {
	STUB_NOT_SUPPORT();
}

