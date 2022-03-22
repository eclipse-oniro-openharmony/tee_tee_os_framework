/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description:
 * This driver part provides facilities for hashing non-secure memory areas.
 *
 * It is a wrapper around CRYS_HASH_xxx API with a few extra features:
 *
 * (1) Given a physical memory span, it maps it into the TrustZone virtual
 *     space; while the driver itself operates on physical addresses, its API
 *     does not provide entry points taking them. Therefore we have to use
 *     sre_mmap()/sre_unmap() before calling the driver. Fortunately they are
 *     not expensive.
 *
 * (2) The Austin driver API currently in use (in contrast to Atlanta) has a
 *     limitation: the length of the block passed to CRYS_HASH_Update() in all
 *     cases except possibly the last call must be a multiple of the hashing
 *     block size (64 or 128 bytes depending on the hash type). Our code lifts
 *     this requirement by accumulating the extra data from each update in a
 *     dedicated buffer
 *
 *         nshasher_context::acc
 *
 *     The entire size of that buffer and the currently used space are held in
 *
 *         nshasher_context::acc_total and
 *         nshasher_context::acc_used
 *
 * The CRYS context is wrapped into a structure nshasher_context instance
 * allocated from a fixed size array contexts[], its index is passed into the
 * user space as a result of nshasher_start() (SW_SYSCALL_NSHASHER_START) and
 * used as a context reference in other 'system calls'. Each context is bound
 * to the caller's PID (nshasher_context::owner), protecting it against the
 * misuse from another TA.
 *
 * Create: 2018-10-29
 */

#include <crys_hash.h>
#include <drv_mem.h> // sre_mmap
#include <drv_module.h>
#include <drv_pal.h>
#include <sre_access_control.h>
#include <sre_syscalls_id_ext.h>
#include <hmdrv_stub.h>

#define KERNEL_MEM_SLICE 0x7C000u
#define MAX_CONTEXT_NUM 4
#define ARGS_IDX_FIRST 1
#define ARGS_IDX_SECOND 2


struct nshasher_context {
	CRYS_HASHUserContext_t crys;
	pid_t owner;
	uint8_t acc[CRYS_HASH_SHA512_BLOCK_SIZE_IN_BYTES];
	uint32_t acc_total;
	uint32_t acc_used;
};

static struct nshasher_context g_contexts[MAX_CONTEXT_NUM];

static uint32_t acc_size(CRYS_HASH_OperationMode_t mode)
{
	switch (mode) {
	case CRYS_HASH_MD5_mode:
	case CRYS_HASH_SHA1_mode:
	case CRYS_HASH_SHA224_mode:
	case CRYS_HASH_SHA256_mode:
		return CRYS_HASH_BLOCK_SIZE_IN_BYTES;

	case CRYS_HASH_SHA384_mode:
	case CRYS_HASH_SHA512_mode:
		return CRYS_HASH_SHA512_BLOCK_SIZE_IN_BYTES;

	default:
		return 0;
	}
}

static uint32_t crys_hash_init(pid_t caller, CRYS_HASH_OperationMode_t mode,
			struct nshasher_context *c)
{
	CRYSError_t res;

	c->acc_used = 0;
	c->acc_total = acc_size(mode);
	if (!c->acc_total) {
		hm_error("unsupported hashing mode %x\n", mode);
		return -1u;
	}

	res = CRYS_HASH_Init(&c->crys, mode);
	if (res != 0) {
		hm_error("CRYS_HASH_Init() error %x\n", res);
		return -1u;
	}
	c->owner = caller;
	return c - g_contexts;
}

/*
 * Allocate and initialize the hasher context. Return the context id or -1u in
 * case of an error.
 */
static uint32_t nshasher_start(pid_t caller, CRYS_HASH_OperationMode_t mode)
{
	struct nshasher_context *c = NULL;

	for (c = g_contexts; c < g_contexts + ARRAY_SIZE(g_contexts); ++c)
		if (!c->owner)
			return crys_hash_init(caller, mode, c);
	hm_error("out of nshasher g_contexts\n");
	return -1u;
}

/* Find and validate the hasher context based on an id supplied by the user. */
static struct nshasher_context *find_context(uint32_t id, pid_t caller)
{
	if ((id < ARRAY_SIZE(g_contexts)) && (g_contexts[id].owner == caller))
		return g_contexts + id;
	hm_error("invalid nshasher context %u\n", id);
	return NULL;
}

/*
 * Complete the hashing, adding the accumulated data remainder if needed,
 * retrieve the hash value and free the context. Return zero on success.
 */
static CRYSError_t nshasher_finish(struct nshasher_context *ctx, uint8_t *out)
{
	CRYS_HASH_Result_t hash;
	CRYSError_t res;
	errno_t rc;

	if ((ctx == NULL) || (out == NULL))
		return -1u;

	ctx->owner = 0;
	res = CRYS_HASH_Update(&ctx->crys, ctx->acc, ctx->acc_used);
	if (res != 0) {
		hm_error("CRYS_HASH_Update(a) error %x\n", res);
		return res;
	}

	res = CRYS_HASH_Finish(&ctx->crys, hash);
	if (res != 0) {
		hm_error("CRYS_HASH_Finish() error %x\n", res);
	} else {
		rc = memcpy_s(out, sizeof(hash), hash, sizeof(hash));
		if (rc != EOK) {
			hm_error("internal error: memcpy_s() failure, rc = %d\n", rc);
			return -1u;
		}
	}

	return res;
}

static CRYSError_t pre_nshasher_update_mapped(struct nshasher_context *ctx,
					uint8_t **data, uint32_t *size,
					uint32_t *len)
{
	errno_t rc;

	/*
	 * If there is some previously accumulated data, we need to fill it up
	 * and hash is first.
	 */
	*len = ctx->acc_total - ctx->acc_used;
	if (*len > *size)
		*len = *size;
	rc = memcpy_s(ctx->acc + ctx->acc_used, *len, *data, *len);
	if (rc != EOK) {
		hm_error("internal error: memcpy_s() failure, rc = %d\n", rc);
		return -1u;
	}
	ctx->acc_used += *len;
	*data += *len;
	*size -= *len;

	return CRYS_OK;
}

/* Hash the supplied data truncating to a multiple of the block size. */
static CRYSError_t truncating_hash_supplied_data(struct nshasher_context *ctx,
						uint8_t **data, uint32_t *size)
{
	CRYSError_t res = CRYS_OK;
	errno_t rc;
	uint32_t len = (*size / ctx->acc_total) * ctx->acc_total;
	uint8_t *tmp_data = NULL;

	if (len == 0)
		return res;

	tmp_data = malloc(len);
	if (tmp_data == NULL) {
		hm_error("malloc failed, size = %u", len);
		ctx->acc_used = 0;
		return -1u;
	}
	rc = memcpy_s(tmp_data, len, *data, len);
	if (rc != EOK) {
		hm_error("internal error: memcpy_s() failure, rc = %d\n", rc);
		ctx->acc_used = 0;
		free(tmp_data);
		return -1u;
	}
	res = CRYS_HASH_Update(&ctx->crys, tmp_data, len);
	free(tmp_data);
	if (res != 0) {
		hm_error("CRYS_HASH_Update(b) error %x\n", res);
		ctx->acc_used = 0;
		return res;
	}
	*data += len;
	*size -= len;
	return res;
}

/*
 * Append more data to the hash. The data should be mapped into the virtual
 * space. Return zero on success.
 */
static CRYSError_t nshasher_update_mapped(struct nshasher_context *ctx,
					uint8_t *data, uint32_t size)
{
	CRYSError_t res;
	errno_t rc;
	uint32_t len;

	if ((ctx == NULL) || (data == NULL))
		return -1u;

	res = pre_nshasher_update_mapped(ctx, &data, &size, &len);
	if (res != CRYS_OK)
		return res;

	/*
	 * Whenever the accumulator is neither full nor empty, we are out of
	 * data for the time being and must wait for more.
	 */
	if (ctx->acc_used && ctx->acc_used != ctx->acc_total)
		return CRYS_OK;

	/* Hash the accumulator. If it is empty, the function does nothing. */
	res = CRYS_HASH_Update(&ctx->crys, ctx->acc, ctx->acc_used);
	if (res != 0) {
		hm_error("CRYS_HASH_Update(a) error %x\n", res);
		ctx->acc_used -= len;
		return res;
	}

	res = truncating_hash_supplied_data(ctx, &data, &size);
	if (res != 0)
		return res;

	/* If something remains, store it in the accumulator. */
	rc = memcpy_s(ctx->acc, ctx->acc_total, data, size);
	if (rc != EOK) {
		hm_error("internal error: memcpy_s() failure, rc = %d\n", rc);
		ctx->acc_used = 0;
		return -1u;
	}
	ctx->acc_used = size;
	return CRYS_OK;
}

/*
 * Map the non-secure physical memory range, pass it to the hasher and unmap.
 * Return zero on success.
 */
static CRYSError_t nshasher_update_ns(struct nshasher_context *ctx,
				paddr_t phy, uint32_t size)
{
	CRYSError_t crys_res = CRYS_OK;
	uint32_t map = 0;
	int res;
	paddr_t end;
	paddr_t len;

	if (ctx == NULL)
		return -1u;

	end = phy + size;
	while (phy < end) {
		len = end - phy;
		if (len > KERNEL_MEM_SLICE)
			len = KERNEL_MEM_SLICE; /* fits in uint32_t */
		res = sre_mmap(phy, len, &map, non_secure, cache);
		if (res != 0) {
			hm_error("sre_mmap() error %d\n", res);
			return -1u;
		}

		crys_res = nshasher_update_mapped(ctx, (uint8_t *)(uintptr_t)map, len);
		if (crys_res != 0) {
			hm_error("nshasher_update_mapped() error %d\n",
				crys_res);
			if (sre_unmap(map, len))
				hm_error("sre_unmap() error");
			return crys_res;
		}

		res = sre_unmap(map, len);
		if (res != 0) {
			hm_error("sre_unmap() error %d\n", res);
			return -1u;
		}

		phy += len;
	}
	return crys_res;
}

static int32_t nshasher_syscall(int swi_id, struct drv_param *params, uint64_t perm)
{
	if (params == NULL || params->args == 0)
		return -1;

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NSHASHER_START,
				perm, ROOTSTATUS_GROUP_PERMISSION)
		args[0] = nshasher_start(__pid, args[0]);
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NSHASHER_FINISH,
				perm, ROOTSTATUS_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[1], sizeof(CRYS_HASH_Result_t));
		ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(CRYS_HASH_Result_t));
		args[0] = nshasher_finish(find_context(args[0], __pid),
					(uint8_t *)(uintptr_t)args[1]);
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NSHASHER_UPDATE_FROM_NS,
				perm, ROOTSTATUS_GROUP_PERMISSION)
		args[0] = nshasher_update_ns(find_context(args[0], __pid),
					(paddr_t)args[ARGS_IDX_FIRST],
					args[ARGS_IDX_SECOND]);
		SYSCALL_END

		default:
			return -1;
	}
	return 0;
}

DECLARE_TC_DRV(
	nonsecure_hasher,   /* name */
	0,                  /* reserved */
	0,                  /* reserved */
	0,                  /* reserved */
	TC_DRV_MODULE_INIT, /* priority */
	NULL,               /* init */
	NULL,               /* handle */
	nshasher_syscall,   /* syscall */
	NULL,               /* suspend */
	NULL                /* resume */
	);
