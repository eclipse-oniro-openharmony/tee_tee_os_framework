/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto hash syscall
 * Create: 2022-01-13
 */
#include "crypto_syscall_hash.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <hmlog.h>
#include "drv_param_ops.h"

static int32_t hash_init_ops(struct ctx_handle_t *ctx, uint32_t *shared_buf,
    const struct crypto_drv_ops_t *ops)
{
    uint32_t alg_type = ctx->alg_type;

    int32_t ret = copy_from_client(ctx->ctx_buffer, ctx->ctx_size,
        (uintptr_t)shared_buf, ctx->ctx_size);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("copy from client failed\n");
        return ret;
    }
    if (ops->hash_init == NULL) {
        hm_error("hardware engine hash init fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->hash_init(shared_buf, alg_type);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do hash init failed. ret = %d\n", ret);
        return ret;
    }

    ret = copy_to_client((uintptr_t)shared_buf, ctx->ctx_size, ctx->ctx_buffer, ctx->ctx_size);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed\n");

    return ret;
}

int32_t hash_init_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    (void)drv;
    if (ops == NULL) {
        hm_error("drv or ops is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (args == 0 || args_len != (uint32_t)sizeof(struct ctx_handle_t)) {
        hm_error("invalid input arg or args_len:%u\n", args_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    struct ctx_handle_t *input = (struct ctx_handle_t *)args;
    if (input->ctx_size > SHARE_MEMORY_MAX_SIZE) {
        hm_error("hash init memory size is invalid. size = %u\n", input->ctx_size);
        return CRYPTO_OVERFLOW;
    }

    uint32_t *shared_buf = malloc_coherent(input->ctx_size);
    if (shared_buf == NULL) {
        hm_error("Failed to malloc shared buf\n");
        return CRYPTO_OVERFLOW;
    }

    (void)memset_s(shared_buf, input->ctx_size, 0, input->ctx_size);

    int32_t ret = hash_init_ops(input, shared_buf, ops);
    if (ret != CRYPTO_SUCCESS)
        hm_error("hash init ops fail\n");

    free(shared_buf);
    return ret;
}

static int32_t hash_update_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->hash_update == NULL) {
        hm_error("hardware engine hash update fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void *ctx_buffer = alloc_and_fill_ctx_buf(crypto_arg);
    if (ctx_buffer == NULL) {
        do_power_off(ops);
        return CRYPTO_OVERFLOW;
    }

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = (uint32_t)ops->hash_update(ctx_buffer, &data_in);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do hash update failed. ret = %d\n", ret);
        free(ctx_buffer);
        return ret;
    }

    crypto_arg--;
    (void)memcpy_s((void *)(uintptr_t)crypto_arg->buffer, crypto_arg->size, ctx_buffer, crypto_arg->size);
    free(ctx_buffer);
    return ret;
}

int32_t hash_update_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hash_update_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);
end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t hash_dofinal_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->hash_dofinal == NULL) {
        hm_error("hardware engine hash dofinal fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void *ctx = alloc_and_fill_ctx_buf(crypto_arg);
    if (ctx == NULL) {
        do_power_off(ops);
        return CRYPTO_OVERFLOW;
    }

    crypto_arg++;
    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    ret = (uint32_t)ops->hash_dofinal(ctx, NULL, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do hash dofinal failed. ret = %d\n", ret);
        free(ctx);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        hm_error("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        free(ctx);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    crypto_arg--;
    (void)memcpy_s((void *)(uintptr_t)crypto_arg->buffer, crypto_arg->size, ctx, crypto_arg->size);
    free(ctx);
    return ret;
}

int32_t hash_dofinal_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hash_dofinal_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t hash_fun_ops(const struct crypto_drv_ops_t *ops,
    struct memref_t *crypto_arg, uint32_t alg_type)
{
    int32_t ret;

    if (ops->hash == NULL) {
        hm_error("hardware engine hash fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->hash(alg_type, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        hm_error("hardware engine do hash failed. ret = %d\n", ret);
        return ret;
    }

    crypto_arg--;
    if (data_out.size > crypto_arg->size) {
        hm_error("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    return ret;
}

int32_t hash_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(&share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hash_fun_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        hm_error("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
