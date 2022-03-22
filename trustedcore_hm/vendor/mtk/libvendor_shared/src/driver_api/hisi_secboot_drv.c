/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Author: h00424236
 * Create: 2019-05-08
 * Description: secboot interface.
 */

#include "hmdrv.h"
#include "mem_page_ops.h"
#include <sre_syscalls_id_ext.h>

#define ADDR_OFFSET 32

__attribute__((visibility("default"))) uint32_t __hisi_secboot_copy_img_from_os(uint32_t soc_type)
{
    uint64_t args[] = {
        (uint64_t)soc_type,
    };

    return hm_drv_call(SW_COPY_IMG_FROM_OS_DRIVER, args, ARRAY_SIZE(args));
}

uint32_t __eiius_encrypto_ctr(paddr_t in_paddr, paddr_t out_paddr, uint32_t in_size, uint8_t *iv_vaddr,
                              uint32_t iv_size, uint32_t mode)
{
    uint64_t args[] = {
        (uint64_t)in_paddr,
        (uint64_t)out_paddr,
        (uint64_t)in_size,
        (uint64_t)(uintptr_t)iv_vaddr, /* Not support 64bit TA now */
        (uint64_t)iv_size,
        (uint64_t)mode,
   };

    return hm_drv_call(SW_EIIUS_ENCRYPTO_DATA, args, ARRAY_SIZE(args));
}

uint32_t __eiius_increment_update(paddr_t old_data_paddr, paddr_t patch_paddr, paddr_t new_data_paddr,
                                  uint32_t old_data_size, uint32_t patch_size, uint32_t new_data_maxsize,
                                  uint32_t *p_new_size)
{
    uint64_t args[] = {
        (uint64_t)old_data_paddr,
        (uint64_t)patch_paddr,
        (uint64_t)new_data_paddr,
        (uint64_t)old_data_size,
        (uint64_t)patch_size,
        (uint64_t)new_data_maxsize,
        (uint64_t)(uintptr_t)p_new_size, /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_EIIUS_INCR_UPDATE, args, ARRAY_SIZE(args));
}

int32_t __eiius_image_verify(paddr_t data_paddr, paddr_t vrl_paddr, uint32_t maxsize, uint32_t is_decrypto)
{
    uint64_t args[] = {
        (uint64_t)data_paddr,
        (uint64_t)vrl_paddr,
        (uint64_t)maxsize,
        (uint64_t)is_decrypto,
    };
    return hm_drv_call(SW_EIIUS_VERIFY_DATA, args, ARRAY_SIZE(args));
}

uint32_t __eiius_get_paddr(uint32_t *low_paddr, uint32_t *high_paddr, uint32_t *p_size, uint32_t addr_type)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)low_paddr,  /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)high_paddr, /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)p_size,     /* Not support 64bit TA now */
        (uint64_t)addr_type,
    };
    return hm_drv_call(SW_EIIUS_GET_PADDR, args, ARRAY_SIZE(args));
}

uint32_t __eiius_secure_memory_map(paddr_t phy_addr, unsigned int size, unsigned int *virt_addr,
                                   unsigned int secure_mode, unsigned int cache_mode)
{
    uint64_t args[] = {
        (uint64_t)phy_addr,
        (uint64_t)size,
        (uint64_t)(uintptr_t)virt_addr, /* Not support 64bit TA now */
        (uint64_t)secure_mode,
        (uint64_t)cache_mode,
    };
    return hm_drv_call(SW_EIIUS_MAP_ADDR, args, ARRAY_SIZE(args));
}

uint32_t __eiius_secure_memory_unmap(unsigned int virt_addr, unsigned int size)
{
    uint64_t args[] = {
        (uint64_t)virt_addr,
        (uint64_t)size,
    };
    return hm_drv_call(SW_EIIUS_UNMAP_ADDR, args, ARRAY_SIZE(args));
}
