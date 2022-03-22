/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: impl video api syscall
 * Author: SecurityEngine
 * Create: 2020/05/21
 */
#include <tee_bit_ops.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <drv_module.h>
#include <hmdrv_stub.h>
#include <hisee_video.h>
#include "chinadrm_manager.h"
#include "drv_pal.h"
#include "drv_param_type.h"

/* syscall dont support pointer member of struct */
struct cdrm_hisee_video_init_param_syscall {
	uint32_t algorithm;
	uint32_t direction;
	uint32_t mode;
	uint32_t padding_type;
	uint32_t keytype;
	uint32_t keylen;
	uint32_t ivlen;

	uint32_t video_type;
	uint32_t pattern_ratio;
	uint32_t buffer_id;
	uint32_t size;
	uint8_t  *outva_base;
};

static void hisee_video_set_init_param(struct cdrm_hisee_video_init_param_syscall *sparam,
				       struct hisee_video_init_param *vparam)
{
	vparam->algorithm     = sparam->algorithm;
	vparam->direction     = sparam->direction;
	vparam->mode          = sparam->mode;
	vparam->padding_type  = sparam->padding_type;
	vparam->keytype       = sparam->keytype;
	vparam->keylen        = sparam->keylen;
	vparam->ivlen         = sparam->ivlen;

	vparam->video_type    = sparam->video_type;
	vparam->pattern_ratio = sparam->pattern_ratio;
	vparam->buffer_id     = sparam->buffer_id;
	vparam->size          = sparam->size;
	vparam->outva_base    = sparam->outva_base;
}

static int hisee_video_syscall_handle(int swi_id, struct drv_param *params, uint64_t permissions)
{
	if (!params || params->args == 0)
		return -1;

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	uint64_t doutlen;

	HANDLE_SYSCALL(swi_id) {
		/* hisee_video_init */
		SYSCALL_PERMISSION(SW_SYSCALL_HISEE_VIDEO_INIT, permissions, MSPE_VIDEO_GROUP_PERMISSION)
			/* ctx: map + copy, allow drv read/write */
			ACCESS_CHECK_A64(args[0], sizeof(struct hisee_video_ctx));
			ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(struct hisee_video_ctx));

			struct hisee_video_init_param vparam = {0};
			/* key/iv: map + copy */
			ACCESS_CHECK_A64(args[3], sizeof(struct cdrm_hisee_video_init_param_syscall));
			hisee_video_set_init_param((struct cdrm_hisee_video_init_param_syscall *)(uintptr_t)args[3], &vparam);
			ACCESS_CHECK_A64(args[1], vparam.keylen);
			ACCESS_CHECK_A64(args[2], vparam.ivlen);
			vparam.pkey = (const uint8_t *)(uintptr_t)args[1];
			vparam.piv  = (const uint8_t *)(uintptr_t)args[2];
			args[0] = hisee_video_init((struct hisee_video_ctx *)(uintptr_t)args[0], &vparam);
		SYSCALL_END

		/* hisee_video_update */
		SYSCALL_PERMISSION(SW_SYSCALL_HISEE_VIDEO_UPDATE, permissions, MSPE_VIDEO_GROUP_PERMISSION)
			/* ctx: map + copy, allow drv read/write */
			ACCESS_CHECK_A64(args[0], sizeof(struct hisee_video_ctx));
			ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(struct hisee_video_ctx));

			uint32_t video_type = hisee_video_get_type((struct hisee_video_ctx *)(uintptr_t)args[0]);

			/* pattern/non-pattern in: map + no-copy */
			ACCESS_CHECK_NOCPY_A64(args[1], args[2]);

			/* pdoutlen: map + copy, allow drv write */
			ACCESS_CHECK_A64(args[4], sizeof(uint64_t));
			ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(uint64_t));
			doutlen = *(uint64_t *)(uintptr_t)args[4];

			/*
			 * pattern out:map + no-copy
			 * non-pattern out:no-map + no-copy
			 */
			if (video_type == HISEE_VIDEO_TYPE_PATTERN)
				ACCESS_CHECK_NOCPY_A64(args[3], doutlen);

			args[0] = hisee_video_update((struct hisee_video_ctx *)(uintptr_t)args[0],
						     (const uint8_t *)(uintptr_t)args[1],
						     (uint32_t)args[2],
						     (uint8_t *)(uintptr_t)args[3],
						     (uint32_t *)(uintptr_t)args[4]);
		SYSCALL_END

		/* hisee_video_dofinal */
		SYSCALL_PERMISSION(SW_SYSCALL_HISEE_VIDEO_DOFINAL, permissions, MSPE_VIDEO_GROUP_PERMISSION)
			/* ctx: map + copy, allow drv read/write */
			ACCESS_CHECK_A64(args[0], sizeof(struct hisee_video_ctx));
			ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(struct hisee_video_ctx));

			uint32_t video_type = hisee_video_get_type((struct hisee_video_ctx *)(uintptr_t)args[0]);

			/* pattern/non-pattern in: map + no-copy */
			ACCESS_CHECK_NOCPY_A64(args[1], args[2]);

			/* pdoutlen: map + copy, allow drv write */
			ACCESS_CHECK_A64(args[4], sizeof(uint64_t));
			ACCESS_WRITE_RIGHT_CHECK(args[4], sizeof(uint64_t));
			doutlen = *(uint64_t *)(uintptr_t)args[4];

			/*
			 * pattern out:map + no-copy
			 * non-pattern out:no-map + no-copy
			 */
			if (video_type == HISEE_VIDEO_TYPE_PATTERN)
				ACCESS_CHECK_NOCPY_A64(args[3], doutlen);

			args[0] = hisee_video_dofinal((struct hisee_video_ctx *)(uintptr_t)args[0],
						      (const uint8_t *)(uintptr_t)args[1],
						      (uint32_t)args[2],
						      (uint8_t *)(uintptr_t)args[3],
						      (uint32_t *)(uintptr_t)args[4]);
		SYSCALL_END

		/* hisee_video_deinit */
		SYSCALL_PERMISSION(SW_SYSCALL_HISEE_VIDEO_DEINIT, permissions, MSPE_VIDEO_GROUP_PERMISSION)
			/* ctx: map + copy, allow drv read/write */
			ACCESS_CHECK_A64(args[0], sizeof(struct hisee_video_ctx));
			ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(struct hisee_video_ctx));

			args[0] = hisee_video_deinit((struct hisee_video_ctx *)(uintptr_t)args[0]);
		SYSCALL_END

		default:
			return -1;
	}

	return 0;
}

DECLARE_TC_DRV(
	hisee_video_syscall_handle_drv,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	NULL,
	NULL,
	hisee_video_syscall_handle,
	NULL,
	NULL
);
