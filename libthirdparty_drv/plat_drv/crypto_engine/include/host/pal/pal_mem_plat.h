/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: define types
 * Author     : SecurityEngine
 * Create     : 2018/08/10
 */
#ifndef __PAL_MEM_PLAT_H__
#define __PAL_MEM_PLAT_H__
#include <common_utils.h>
#include <pal_errno.h>
#include <eps_ddr_layout_define.h>
#include <soc_baseaddr_interface.h>

#ifndef pal_write_u32
#define pal_write_u32(data, addr)      do { \
	u32 __value = (u32)(data); \
	\
	(*((volatile u32 *)PTR(addr)) = __value); \
} while (0)
#endif /* pal_write_u32 */

#ifndef pal_read_u32
#define pal_read_u32(addr)             (*((volatile u32 *)PTR(addr)))
#endif /* pal_read_u32 */

err_bsp_t pal_ddr_mgr_init(void);

/* return size of symm workspace */
u32 pal_get_symm_workspace(u32 id, u64 *va, u64 *pa);

#endif /* __PAL_MEM_PLAT_H__ */
