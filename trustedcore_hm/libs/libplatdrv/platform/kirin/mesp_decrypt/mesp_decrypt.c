/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platdrv in TEE for TA decrypt key through ipc_s
 */

#include "mesp_decrypt.h"
#include <sys/usrsyscall_ext.h>
#include <register_ops.h>
#include <sched.h>
#include <drv_pal.h>
#include <drv_module.h>
#include <sre_typedef.h>
#include <ipc.h>
#include <hisee_seceng.h>
#include "sre_access_control.h"
#include <hmdrv_stub.h>
#include "tee_log.h"
#include "sre_syscalls_id_ext.h"
#include "securec.h"
#include "sre_hwi.h"

static int32_t mesp_decrypt(void *buf, int32_t length)
{
	err_bsp_t ret;

	if (buf == NULL) {
		tloge("IPC MESP decrypt: inpit buf is NULL\n");
		return -1;
	}
	if (length != sizeof(struct data_for_mesp)) {
		tloge("IPC MESP decrypt: length = %d, inpit buf length error\n", length);
		return -1;
	}
	struct data_for_mesp *msg = buf;
	struct encrypt_package *encypt_pkg = (struct encrypt_package *)(msg->for_mesp);
	struct hisee_hiai_data hiai_data = {
		.alg = SYMM_ALGORITHM_AES,
		.mode = SYMM_MODE_CBC,
		.keytype = SYMM_KEYTYPE_GID,
		.vtype = HIAI_VERIFY_SHA256,
		.vvalue = {
			.pdata = encypt_pkg->hash,
			.size = HASH_SIZE
		},
		.iv = {
			.pdata = encypt_pkg->iv,
			.size = IV_SIZE
		},
		.derivein = {
			.pdata = encypt_pkg->derivein,
			.size = DERIVEIN_SIZE
		},
		.pubkey = {
			.curve_id = CURVE_ID_BRAINPOOLP256R1,
			.pubx = {
				.pdata = msg->public_key,
				.size = 32 /* x of public_key */
			},
			.puby = {
				.pdata = msg->public_key + 32,
				.size = 32 /* y of public_key */
			},
		},
	};

	/* Decrypt the data and get the joint key */
	ret =  hisee_hiai_key_compute(&hiai_data, encypt_pkg->private_key,
		PRIVATE_KEY_SIZE, msg->output_data, OUTPUT_SIZE);
	if (ret != BSP_RET_OK) {
		tloge("hisee_hiai_key_compute return %d error\n", ret);
		return -1;
	}
	/* The first 32 bits of the joint key are valid */
	msg->real_output_size = 32;

	return 0;
}

int32_t mesp_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
	int32_t ret = 0;
	uint64_t *args = NULL;

	if (params == NULL || params->args == 0)
		return -1;
	args = (uint64_t *)(uintptr_t)params->args;
	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NPU_MESP_DECRYPT, permissions,
			AI_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], args[1]);
		ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
		ret = mesp_decrypt((void *)(uintptr_t)args[0], args[1]);
		SYSCALL_END
		default:
			return -1;
	}

	return ret;
}

/* register sys_call, load to specified section beside the other drv */
DECLARE_TC_DRV(
	mesp_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	mesp_syscall,
	NULL,
	NULL
);
