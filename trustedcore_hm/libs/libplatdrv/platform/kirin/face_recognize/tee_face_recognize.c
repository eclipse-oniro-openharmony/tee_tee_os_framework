#include <stdio.h>
#include <drv_module.h>
#include <mem_mode.h>
#include <tee_log.h>
#include <sion.h>
#include "sre_task.h"
#include "mem_mode.h" // secure
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "drv_task_map.h"
#include "drv_pal.h"
#include "procmgr_ext.h"
#include "sre_access_control.h"
#include "tee_face_recognize.h"
#include "tee_defines.h"
#include "secmem.h"
#ifdef SWING_SUPPORTED
#include "iomcu_ddr_map.h"
#endif

#ifdef TEE_SUPPORT_TZMP2
extern s32 hisi_sion_check_mem(paddr_t addr, u32 size, u32 protect_id);
#endif
extern pid_t hm_getpid();
extern int drv_map_paddr_to_task(paddr_t phy_addr, unsigned int size,
				 unsigned int *virt_addr,
				 unsigned int secure_mode,
				 unsigned int cache_mode);
extern int drv_unmap_from_task(unsigned int virt_addr, unsigned int size);

#define SYS_CNTCV_HIGH (0xFFF05000) /* Same as RTC_BASE_ADDR */

extern unsigned int isSecureContentMemory(paddr_t addr, unsigned int size);

unsigned int  fr_read_current_time(void)
{
	unsigned int rtc_time;
	rtc_time = *(volatile unsigned int *)SYS_CNTCV_HIGH;

	return rtc_time;
}

int fr_secure_memory_map(paddr_t phy_addr, unsigned int size,
			 unsigned int *virt_addr, unsigned int secure_mode, unsigned int cache_mode)
{
	if (secure_mode == secure) {
		if (fr_is_secure_memory(phy_addr, size, SEC_TASK_SEC) != 1) {
			tloge("secure mem check failed\n");
			return -1;
		}
	}

    return drv_map_paddr_to_task(phy_addr, size, virt_addr, secure_mode, cache_mode);
}

int fr_secure_memory_unmap(unsigned int virt_addr, unsigned int size)
{
	return drv_unmap_from_task(virt_addr, size);
}

int fr_is_secure_memory(paddr_t addr, unsigned int size,
			unsigned int protect_id)
{
#ifdef SWING_SUPPORTED
	if ((addr >= (DDR_TINY_RESERVE_ADDR_AP + DDR_TINY_RESERVE_SIZE - DDR_TINY_FACEID_RESERVE_SIZE)) &&
			((addr + size) <= (DDR_TINY_RESERVE_ADDR_AP + DDR_TINY_RESERVE_SIZE))) {
		return 1;
	}
#endif
#ifdef TEE_SUPPORT_TZMP2
	return (int)hisi_sion_check_mem(addr, size, protect_id);
#else
	return (int)isSecureContentMemory(addr, size);
#endif
}

int fr_sion_pool_flag_set(unsigned int type)
{
#ifdef TEE_SUPPORT_TZMP2
	int  ui32Result;
	ui32Result = sion_pool_flag_set(type);
	return ui32Result;
#else
	return 0;
#endif
}

int fr_sion_pool_flag_unset(unsigned int type)
{
#ifdef TEE_SUPPORT_TZMP2
	int  ui32Result;
	ui32Result = sion_pool_flag_unset(type);
	return ui32Result;
#else
	return 0;
#endif
}

int fr_get_static_phy_addr(unsigned int *addr, unsigned int type, unsigned int index, unsigned int size)
{
	(void)addr;
	(void)type;
	(void)index;
	(void)size;
#ifdef SWING_SUPPORTED
	if (addr && size && (type == 0)) {
		unsigned int offset = index * size;
		if ((offset + size) < DDR_TINY_FACEID_RESERVE_SIZE) {
			*addr = DDR_TINY_RESERVE_ADDR_AP + DDR_TINY_RESERVE_SIZE - DDR_TINY_FACEID_RESERVE_SIZE + offset;
			return 0;
		}
	}
#endif
	return -1;
}

#include <hmdrv_stub.h>        // hack for `HANDLE_SYSCALL`
int face_recognize_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	uint64_t uwRet = 0;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them */
	if (params == NULL || params->args == 0)
		return -1;
	uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_FR_SECURE_TEE_MMAP, permissions,
				   FR_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[2], sizeof(uint64_t));
		ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(uint64_t));
		uwRet = (uint64_t)fr_secure_memory_map(args[0],
						     (unsigned int)args[1],
						     (unsigned int *)(uintptr_t)args[2], (unsigned int)args[3], (unsigned int)args[4]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_SECURE_TEE_UNMAP, permissions,
				   FR_GROUP_PERMISSION)
		uwRet = (uint64_t)fr_secure_memory_unmap((unsigned int)args[0],
						       (unsigned int)args[1]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_SECURE_ISSECUREMEM, permissions,
				   FR_GROUP_PERMISSION)
		uwRet = (uint64_t)fr_is_secure_memory(args[0],
						    (unsigned int)args[1], (unsigned int)args[2]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_SECURE_ION_SET, permissions,
				   FR_GROUP_PERMISSION)
		uwRet = (uint64_t)fr_sion_pool_flag_set((unsigned int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_SECURE_ION_UNSET, permissions,
				   FR_GROUP_PERMISSION)
		uwRet = (uint64_t)fr_sion_pool_flag_unset((unsigned int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_READ_CURRENT_TIME, permissions,
				   FR_GROUP_PERMISSION)
		uwRet = (uint64_t)fr_read_current_time();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FR_GET_STATIC_PHY_ADDR, permissions,
				   FR_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(uint64_t));
		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(uint64_t));
		uwRet = (uint64_t)fr_get_static_phy_addr((unsigned int *)(uintptr_t)args[0], (unsigned int)args[1],
				   (unsigned int)args[2], (unsigned int)args[3]);
		args[0] = uwRet;
		SYSCALL_END
	default:
		return -1;
	}
	return 0;
}
DECLARE_TC_DRV(
	face_recognize,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	face_recognize_syscall,
	NULL,
	NULL
);
