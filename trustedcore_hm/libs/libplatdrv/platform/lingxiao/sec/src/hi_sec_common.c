/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: 平台相关功能
 * Author: o00302765
 * Create: 2019-10-22
 */

#include <drv_module.h>
#include "hi_sec_common.h"
#include "hi_sec_drv.h"
#include "sre_access_control.h"
#include "sre_syscalls_id.h"
#include "sec_adapt.h"
#include <hmdrv_stub.h>
#include "drv_param_type.h"

hi_void hi_printk(const char *fmt, ...)
{
	return;
}

hi_void hi_sdk_l0_write_reg(hi_uint32 addr, hi_uint32 *var)
{
	hi_uint32 *reg = HI_NULL;

	if (var == HI_NULL) {
		return;
	}

	reg = (hi_uint32 *)(addr);
	(*reg) = (*var);

	return;
}

hi_void hi_sdk_l0_read_reg(hi_uint32 addr, hi_uint32 *var)
{
	hi_uint32 *reg = HI_NULL;

	if (var == HI_NULL) {
		return;
	}

	reg = (hi_uint32 *)(addr);
	(*var) = (*reg);

	return;
}

hi_void hi_udelay(hi_uint32 nus)
{
    __asm__ volatile("nop");
    return;
}

uintptr_t hi_sec_get_phyaddr(hi_uchar8 *buf, hi_uint32 buflen, hi_uint32 dir)
{
    //return hi_dma_map_single(&dev, buf, buflen, dir);
}

hi_void hi_sec_release_phyaddr(uintptr_t phyaddr, hi_uint32 buflen, hi_uint32 dir)
{
    //hi_dma_unmap_single(&dev, phyaddr, buflen, dir);
}

hi_void *hi_sec_alloc_phyaddr(hi_uint32 size, uintptr_t *phyaddr)
{
    //return hi_dma_alloc_coherent(&dev, size, (dma_addr_t *)phyaddr, GFP_KERNEL);
}

hi_void hi_sec_free_phyaddr(hi_uint32 size, hi_void *buf, uintptr_t phyaddr)
{
    //hi_dma_free_coherent(&dev, size, buf, (dma_addr_t)phyaddr);
}

/* 内存屏障, 确保符数据已经更新到DDR */
hi_void hi_sec_dsb(hi_void)
{
    //dsb();
}

hi_void *hi_sec_dma_malloc(hi_uint32 size)
{
    //return hi_dmamalloc(size);
}

hi_void hi_sec_dma_free(hi_void *addr)
{
    //hi_free(addr);
}

hi_int32 hi_sec_com_init(hi_void)
{
	hi_int32 ret;
	ret = hi_sec_drv_init();
	if (ret != HI_RET_SUCC) {
		return ret;
	}

	return HI_RET_SUCC;
}

hi_void hi_sec_com_exit(hi_void)
{
	hi_sec_drv_exit();
}

int32_t trng_get_random(uint8_t *rnd, uint32_t rnd_len)
{
    int32_t ret;
    if (rnd == NULL)
        return -1;
    ret = hi_sec_gen_trng(rnd, rnd_len);
    return ret;
}

int sec_drv_call(int swi_id, struct drv_param *params, uint64_t permissions)
{
	hi_int32 ret = 0;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them
	 * Not support 64bit TA now
	 */
	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_SEC_DERIVEKEY, permissions, CC_KEY_GROUP_PERMISSION)
		ACCESS_CHECK(args[0], args[1]);
		ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
		ACCESS_CHECK(args[2], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], args[1]);
        ret = hi_sec_derive_key((uint8_t *)args[0], (uint32_t)args[1], (uint8_t *)args[2]);
		args[0] = ret;
		SYSCALL_END;

		SYSCALL_PERMISSION(SW_SYSCALL_SEC_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
		ACCESS_CHECK(args[0], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        ret = trng_get_random((uint8_t *)args[0], (uint32_t)args[1]);
		args[0] = ret;
		SYSCALL_END;
	default:
		return -1;
	}

	return 0;
}

DECLARE_TC_DRV(
	secdriver_init,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	hi_sec_com_init,
	NULL,
	sec_drv_call,
	NULL,
	NULL
);
