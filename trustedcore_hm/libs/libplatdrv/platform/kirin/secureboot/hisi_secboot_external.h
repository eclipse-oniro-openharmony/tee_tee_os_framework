/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hisi_secboot_external.h main for modem and other soc
 * Create: 2019/9/19
 */
#ifndef __HISI_SECBOOT_EXTERNAL_H__
#define __HISI_SECBOOT_EXTERNAL_H__
/*
 * include this for SECBOOT_LOCKSTATE, it should be
 * not include if lib want to complile outside teeos
 * and definitions should be defined in this file
 */
#include "hisi_seclock.h"
#include <stdint.h>

/* struct for addr process */
struct process_info {
	UINT32 soc_type;
	UINT32 (*process_init)(paddr_t soc_addr);
	UINT32 (*process_succ)(void);
	UINT32 (*process_fail)(void);
};

/* define of max len of image, this should be same as that in secboot.h */
#ifndef SECBOOT_IMGNAME_MAXLEN
#define SECBOOT_IMGNAME_MAXLEN 36
#endif

/* struct for img_info(soc_type with name) */
struct img_info {
	UINT32 soc_type;
	UINT8 soc_name[SECBOOT_IMGNAME_MAXLEN];
};

/* struct for verify ops */
struct verify_struct_op {
	UINT32 soc_type;
	UINT32 (*reset)(UINT32 soc_type);
	UINT32 (*set)(UINT32 soc_type);
	UINT32 (*verification)(UINT32 soc_type, UINT32 vrl_addr,
		paddr_t core_id, SECBOOT_LOCKSTATE lock_state);
	UINT32 (*copy)(UINT32 soc_type, UINT32 offset, const paddr_t addr,
		UINT32 len);
};

/* used for modem */
UINT32 secboot_modem_register(struct verify_struct_op *modem_op);
UINT32 secboot_get_secimage_size(UINT32 vrl_addr, UINT32 *img_size);
/* vrl_addr should be virtual addr in drv, while imageaddress should be phy in drv */
UINT32 secboot_soc_verification(UINT32 vrladdress, paddr_t imageaddress,
				const char *imagenameptr, UINT32 isprimvrl,
				SECBOOT_LOCKSTATE lock_state);
void secboot_dump_vrl(void);
/*
 * universal verify interface
 * vrl_addr and img_addr should be virtual addr in drv, all addr must be cachealign
 * this works both v1 and v2 version
 */

UINT32 secboot_verify(UINT32 vrl_addr, size_t vrl_size, UINT32 img_addr,
		      size_t img_size, const char *img_name, size_t name_len);
#endif
