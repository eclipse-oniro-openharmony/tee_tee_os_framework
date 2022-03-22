#include "secmem_drv.h"
#include <stdint.h>
#include <hm_mman_ext.h>
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_internal_api.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"

/*
 * RTOSck INSE API
 * in rtosck:
 *   __XXXX are used by el0 apps (e.g.: ta)
 *   XXXX are used by kernel (e.g.: drivers)
 * due to the drivers now are moved to el0, most apis we need to
 * provide two version.
 */

#ifdef TEE_SUPPORT_TZMP2
__attribute__((visibility("default"))) int __sion_ioctl(int ion_ta_tag, void *mcl)
{
    uint64_t args[] = {
        (uint64_t)ion_ta_tag,
        (uint64_t)(uintptr_t)mcl,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_ION_IOCTL_SECTA, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
unsigned int sion_mmap(void *sglist, unsigned int size, unsigned int protect_id, int mode, int cached, int used_by_ta)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)sglist, (uint64_t)size, (uint64_t)protect_id, (uint64_t)mode, (uint64_t)cached,
        (uint64_t)used_by_ta,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_ION_MMAP, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int sion_munmap(void *sglist, unsigned int va, unsigned int size, unsigned int protect_id, int mode, int used_by_ta)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)sglist, (uint64_t)va,   (uint64_t)size,
        (uint64_t)protect_id,        (uint64_t)mode, (uint64_t)used_by_ta,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_ION_MUNMAP, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)sglist,
        (uint64_t)feature_id,
        (uint64_t)ddr_cfg_type,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_DDR_CFG, args, ARRAY_SIZE(args));
}

#endif
