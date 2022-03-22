#include <stdint.h>
#include <stdint.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"
#include "secureisp_tee.h"

/*
 * RTOSck INSE API
 * in rtosck:
 *   __XXXX are used by el0 apps (e.g.: ta)
 *   XXXX are used by kernel (e.g.: drivers)
 * due to the drivers now are moved to el0, most apis we need to
 * provide two version.
 */

int __secisp_disreset()
{
	uint64_t args[] = {
	};
	return hm_drv_call(ISP_SYSCALL_DISRESET, args, ARRAY_SIZE(args));
}

int __secisp_reset(void)
{
	uint64_t args[] = {
	};
	return hm_drv_call(ISP_SYSCALL_RESET, args, ARRAY_SIZE(args));
}

int __secisp_nonsec_map(void *sglist, uint32_t sg_size, void *buffer, uint32_t buffer_size)
{
	uint64_t args[] = {
		(uint64_t)(uintptr_t)sglist,
		(uint64_t)sg_size,
		(uint64_t)(uintptr_t)buffer,
		(uint64_t)buffer_size,
	};
	return hm_drv_call(ISP_SYSCALL_NONSEC_MEM_MAP, args, ARRAY_SIZE(args));
}

int __secisp_nonsec_unmap(void *sglist, uint32_t sg_size, void *buffer, uint32_t buffer_size)
{
	uint64_t args[] = {
		(uint64_t)(uintptr_t)sglist,
		(uint64_t)sg_size,
		(uint64_t)(uintptr_t)buffer,
		(uint64_t)buffer_size,
	};
	return hm_drv_call(ISP_SYSCALL_NONSEC_MEM_UNMAP, args, ARRAY_SIZE(args));
}

int __secisp_sec_map(uint32_t sfd, uint32_t sfd_size, void *buffer, uint32_t buffer_size)
{
	uint64_t args[] = {
		(uint64_t)sfd,
		(uint64_t)sfd_size,
		(uint64_t)(uintptr_t)buffer,
		(uint64_t)buffer_size,
	};
	return hm_drv_call(ISP_SYSCALL_SEC_MEM_MAP, args, ARRAY_SIZE(args));
}
int __secisp_sec_unmap(uint32_t sfd, uint32_t sfd_size, void *buffer, uint32_t buffer_size)
{
	uint64_t args[] = {
		(uint64_t)sfd,
		(uint64_t)sfd_size,
		(uint64_t)(uintptr_t)buffer,
		(uint64_t)buffer_size,
	};
	return hm_drv_call(ISP_SYSCALL_SEC_MEM_UNMAP, args, ARRAY_SIZE(args));
}

