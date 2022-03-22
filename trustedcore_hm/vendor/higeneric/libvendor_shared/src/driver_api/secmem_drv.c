#include "secmem_drv.h"
#include <stdint.h>
#include <hm_mman_ext.h>
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_internal_api.h"

#ifdef TEE_SUPPORT_VLTMM_SRV
#include <vltmm_client_api.h>
#endif

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"

/*
 * RTOSck integrated Secure Element API
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

__attribute__((visibility("default"))) \
unsigned int sion_mmap_sfd(unsigned int sfd, unsigned int size, unsigned int protect_id, int mode, int cached, int used_by_ta)
{
    uint64_t args[] = {
        (uint64_t)sfd, (uint64_t)size, (uint64_t)protect_id, (uint64_t)mode, (uint64_t)cached,
        (uint64_t)used_by_ta,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_ION_MMAP_SFD, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int sion_munmap_sfd(unsigned int sfd, unsigned int va, unsigned int size, unsigned int protect_id, int mode, int used_by_ta)
{
    uint64_t args[] = {
        (uint64_t)sfd, (uint64_t)va,   (uint64_t)size,
        (uint64_t)protect_id,        (uint64_t)mode, (uint64_t)used_by_ta,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_ION_MUNMAP_SFD, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int sion_ddr_sec_cfg(u16 buffer_id, unsigned int size,
				int cached, int feature_id, int ddr_cfg_type)
{
    uint64_t args[] = {
        (uint64_t)buffer_id,
        (uint64_t)size,
        (uint64_t)cached,
        (uint64_t)feature_id,
        (uint64_t)ddr_cfg_type,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_DDR_CFG_SFD, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int sion_create_smmu_domain(u32 protect_id, u64 pgtable_addr,
			    u32 pgtable_size)
{
    uint64_t args[] = {
        (uint64_t)protect_id,
        (uint64_t)pgtable_addr,
        (uint64_t)pgtable_size,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_CREATE_DOMAIN, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int sion_destroy_smmu_domain(u32 protect_id)
{
    uint64_t args[] = {
        (uint64_t)protect_id,
    };
    return hm_drv_call(SW_SYSCALL_SECMEM_DESTROY_DOMAIN, args, ARRAY_SIZE(args));
}

#endif
__attribute__((visibility("default"))) \
int secmem_get_version(void)
{
	int version = VERSION_1;

#ifdef TEE_SUPPORT_VLTMM_SRV
	version = VERSION_2;
#endif

	return version;
}

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

__attribute__((visibility("default"))) \
int secmem_smmu_domain_init(uint32_t sid, uint32_t size)
{
#ifdef TEE_SUPPORT_VLTMM_SRV
	return vlt_create_siommu_domain(sid, size);
#endif
	UNUSED(sid);
	UNUSED(size);
	return 0;
}

__attribute__((visibility("default"))) \
int secmem_smmu_domain_destroy(uint32_t sid)
{
#ifdef TEE_SUPPORT_VLTMM_SRV
	return vlt_destroy_siommu_domain(sid);
#endif
	UNUSED(sid);
	return 0;
}
