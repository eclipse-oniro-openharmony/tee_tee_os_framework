/*Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: derive cuid
 * Create: 2021/01/29
 */

#ifndef __SEC_DERIVE_CUID_H__
#define __SEC_DERIVE_CUID_H__

#include <stdint.h>

#define CUID_BYTES            0x20
#define CUID_PART_BYTES       0x10
#define CUID_NOT_DERIVE_ERR   0x0ffff0001U

#ifdef CONFIG_CC_CUID
uint32_t secboot_get_cuid(uint8_t *cuid, uint32_t len);

#else
static inline uint32_t secboot_get_cuid(uint8_t *cuid, uint32_t len)
{
	(void)cuid;
	(void)len;
	tloge("%s not implement\n", __func__);
	return CUID_NOT_DERIVE_ERR;
}
#endif


#endif
