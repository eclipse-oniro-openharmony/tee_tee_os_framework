/* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: derive cuid
 * Create: 2021/01/29
 */

#include "sec_derive_cuid.h"
#include <sre_typedef.h>
#include <drv_module.h>
#include <securec.h>
#include <tee_log.h>
#include "cc_power.h"
#include "cc_driver_adapt.h"
#include "crypto_driver_adaptor.h"

#define CUID_SEED1 { 0x2e, 0xe9, 0x44, 0x63, 0x6c, 0x6d, 0x34, 0x2e, \
		     0xb5, 0xc9, 0x40, 0x51, 0x84, 0xd2, 0x96, 0x16 }

#define CUID_SEED2 { 0x94, 0xec, 0x2f, 0x2e, 0xa9, 0x2a, 0x32, 0xf8, \
		     0x22, 0x85, 0x5a, 0xbc, 0x57, 0xef, 0x9d, 0xb0 }


uint32_t secboot_get_cuid(uint8_t *cuid, uint32_t len)
{
	int32_t ret;
	uint32_t rc;
	struct memref_t in = { 0 };
	struct memref_t out = { 0 };
	uint8_t cuid_seed1[] = CUID_SEED1;
	uint8_t cuid_seed2[] = CUID_SEED2;
	uint8_t tmp_out[CUID_PART_BYTES] = { 0 };

	if (!cuid || len < CUID_BYTES) {
		tloge("%s, param error\n", __func__);
		return 1;
	}

	in.buffer = (uint64_t)cuid_seed1;
	in.size = sizeof(cuid_seed1);
	out.buffer = (uint64_t)tmp_out;
	out.size = sizeof(tmp_out);

	/* devide cuid into two 16 bytes parts, then put them together */
	ret = hw_derive_root_key(UTIL_ROOT_KEY, &in, &out);
	if (ret != 0) {
		tloge("error 0x%x, get cuid part1\n", ret);
		return ret;
	}

	if (out.size < CUID_PART_BYTES) {
		tloge("invalid cuid part1 size\n");
		return 1;
	}
	rc = memcpy_s(cuid, len, (uint8_t *)(uintptr_t)out.buffer, CUID_PART_BYTES);
	if (rc != EOK) {
		tloge("error 0x%x, cp cuid part1\n", rc);
		return 1;
	}

	in.buffer = (uint64_t)cuid_seed2;
	out.size = sizeof(tmp_out);
	ret = hw_derive_root_key(UTIL_ROOT_KEY, &in, &out);
	if (ret != 0) {
		tloge("error 0x%x, get cuid part2\n", ret);
		return ret;
	}

	rc = memcpy_s(cuid + CUID_PART_BYTES, len - CUID_PART_BYTES,
		      (uint8_t *)(uintptr_t)out.buffer, out.size);
	if (rc != EOK) {
		tloge("error 0x%x, cp cuid part2\n", rc);
		return 1;
	}

	return 0;
}
