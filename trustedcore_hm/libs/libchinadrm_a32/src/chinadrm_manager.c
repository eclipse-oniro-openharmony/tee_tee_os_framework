/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: impl for ta.
 * Author: SecurityEngine
 * Create: 2020/05/21
 */
#include "chinadrm_manager.h"
#include <sre_syscalls_id.h>
#include <hmdrv.h>

#define hmccmgr_call(...)                 hm_drv_call(__VA_ARGS__)
#define CDRM_SYSCALL_PARAM_CONVERT(value) (uint64_t)(uintptr_t)(value)

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
	uint32_t cipher_blk_size;
	uint32_t plain_blk_size;
	uint32_t buffer_id;
	uint32_t size;
	uint8_t  *outva_base;
};

static int32_t cdrm_hisee_video_init_syscall(void *pctx,
					     const uint8_t *pkey, const uint8_t *piv,
					     struct cdrm_hisee_video_init_param_syscall *param)
{
	uint64_t args[] = {
		CDRM_SYSCALL_PARAM_CONVERT(pctx),
		CDRM_SYSCALL_PARAM_CONVERT(pkey),
		CDRM_SYSCALL_PARAM_CONVERT(piv),
		CDRM_SYSCALL_PARAM_CONVERT(param),
	};

	return (int32_t)hmccmgr_call(SW_SYSCALL_SEE_VIDEO_INIT, args, ARRAY_SIZE(args));
}

int32_t cdrm_hisee_video_init(void *pctx, struct cdrm_hisee_video_init_param *param)
{
	struct cdrm_hisee_video_init_param_syscall sparam;

	sparam.algorithm     = param->algorithm;
	sparam.direction     = param->direction;
	sparam.mode          = param->mode;
	sparam.padding_type  = param->padding_type;
	sparam.keytype       = param->keytype;
	sparam.keylen        = param->keylen;
	sparam.ivlen         = param->ivlen;

	sparam.video_type      = param->video_type;
	sparam.cipher_blk_size = param->cipher_blk_size;
	sparam.plain_blk_size  = param->plain_blk_size;
	sparam.buffer_id       = param->buffer_id;
	sparam.size            = param->size;
	sparam.outva_base      = param->outva_base;

	return cdrm_hisee_video_init_syscall(pctx, param->pkey, param->piv, &sparam);
}

int32_t cdrm_hisee_video_update(void *pctx,
				const uint8_t *pdin, uint32_t dinlen,
				uint8_t *pdout, uint32_t *pdoutlen)
{
	uint64_t args[] = {
		CDRM_SYSCALL_PARAM_CONVERT(pctx),
		CDRM_SYSCALL_PARAM_CONVERT(pdin),
		CDRM_SYSCALL_PARAM_CONVERT(dinlen),
		CDRM_SYSCALL_PARAM_CONVERT(pdout),
		CDRM_SYSCALL_PARAM_CONVERT(pdoutlen),
	};

	return (int32_t)hmccmgr_call(SW_SYSCALL_SEE_VIDEO_UPDATE, args, ARRAY_SIZE(args));
}

int32_t cdrm_hisee_video_dofinal(void *pctx,
				 const uint8_t *pdin, uint32_t dinlen,
				 uint8_t *pdout, uint32_t *pdoutlen)
{
	uint64_t args[] = {
		CDRM_SYSCALL_PARAM_CONVERT(pctx),
		CDRM_SYSCALL_PARAM_CONVERT(pdin),
		CDRM_SYSCALL_PARAM_CONVERT(dinlen),
		CDRM_SYSCALL_PARAM_CONVERT(pdout),
		CDRM_SYSCALL_PARAM_CONVERT(pdoutlen),
	};

	return (int32_t)hmccmgr_call(SW_SYSCALL_SEE_VIDEO_DOFINAL, args, ARRAY_SIZE(args));
}

int32_t cdrm_hisee_video_deinit(void *pctx)
{
	uint64_t args[] = {
		CDRM_SYSCALL_PARAM_CONVERT(pctx),
	};

	return (int32_t)hmccmgr_call(SW_SYSCALL_SEE_VIDEO_DEINIT, args, ARRAY_SIZE(args));
}
